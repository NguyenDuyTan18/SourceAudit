"""Prove a few local facts about Python arguments reported by Semgrep.

This script parses source as data. It never imports or executes scanned modules.
"""

import ast
import json
import re
import sys
from pathlib import Path
from string import Formatter


UNKNOWN, TEXT, TEXT_LIST, NO_APOSTROPHE, SAFE_XPATH = (object() for _ in range(5))
XPATH_LITERAL = re.compile(r"(?:/{1,2}[A-Za-z_][\w.-]*)+\[@[A-Za-z_][\w.-]*='")
TEXT_FIELDS = {"args", "form", "values", "headers", "cookies"}
DNS_HOST = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")


def canonical(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, "")
    if isinstance(node, ast.Attribute):
        base = canonical(node.value, aliases)
        return base + "." + node.attr if base else ""
    return ""


def request_field(node, aliases):
    return (
        isinstance(node, ast.Attribute)
        and node.attr in TEXT_FIELDS
        and canonical(node.value, aliases) == "flask.request"
    )


def primitive(value):
    if type(value) is bool:
        return value
    if type(value) is int and abs(value) <= 10**9:
        return value
    if type(value) is str and len(value) <= 4096:
        return value
    return UNKNOWN


def percent_format(template, values):
    if not re.fullmatch(r"(?:[^%]|%%|%s)*", template):
        return UNKNOWN
    if not all(type(value) in (str, int, bool) for value in values):
        return UNKNOWN
    if len(template) + sum(len(str(value)) for value in values) > 4096:
        return UNKNOWN
    try:
        return primitive(template % tuple(values))
    except TypeError:
        return UNKNOWN


def positional_format(template, values):
    if not all(type(value) in (str, int, bool) for value in values):
        return UNKNOWN
    try:
        fields = [part for part in Formatter().parse(template) if part[1] is not None]
        if any(spec or conversion or (field and not re.fullmatch(r"[0-9]{1,3}", field))
               for _, field, spec, conversion in fields):
            return UNKNOWN
        if len(template) + len(fields) * max((len(str(value)) for value in values), default=0) > 4096:
            return UNKNOWN
        return primitive(template.format(*values))
    except (ValueError, IndexError):
        return UNKNOWN


def value_of(node, facts, aliases):
    if isinstance(node, ast.Constant):
        return primitive(node.value)
    if isinstance(node, ast.Name):
        return facts.get(node.id, UNKNOWN)
    if isinstance(node, ast.IfExp):
        cond = value_of(node.test, facts, aliases)
        if type(cond) is bool:
            return value_of(node.body if cond else node.orelse, facts, aliases)
        yes, no = (value_of(part, facts, aliases) for part in (node.body, node.orelse))
        if all(v is TEXT or v is NO_APOSTROPHE or type(v) is str for v in (yes, no)):
            return TEXT
    if isinstance(node, ast.BinOp):
        left, right = (value_of(part, facts, aliases) for part in (node.left, node.right))
        if type(left) is type(right) is int:
            if isinstance(node.op, ast.Add):
                return primitive(left + right)
            if isinstance(node.op, ast.Sub):
                return primitive(left - right)
            if isinstance(node.op, ast.Mult):
                return primitive(left * right)
        if type(left) is type(right) is str and isinstance(node.op, ast.Add):
            return primitive(left + right)
        if type(left) is str and isinstance(node.op, ast.Mod):
            items = [value_of(part, facts, aliases) for part in node.right.elts] if isinstance(node.right, ast.Tuple) else [right]
            return percent_format(left, items)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = (value_of(part, facts, aliases) for part in (node.left, node.comparators[0]))
        op = node.ops[0]
        if type(left) is type(right) and type(left) in (str, int, bool):
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
            if isinstance(op, ast.Lt):
                return left < right
            if isinstance(op, ast.LtE):
                return left <= right
            if isinstance(op, ast.Gt):
                return left > right
            if isinstance(op, ast.GtE):
                return left >= right
    if isinstance(node, ast.Subscript):
        container = value_of(node.value, facts, aliases)
        index = value_of(node.slice, facts, aliases)
        if type(container) is str and type(index) is int and -len(container) <= index < len(container):
            return container[index]
        if request_field(node.value, aliases) or (
            isinstance(node.value, ast.Call)
            and not isinstance(node.slice, (ast.Slice, ast.Tuple))
            and container is TEXT_LIST
        ):
            return TEXT
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and not node.keywords:
        receiver = node.func.value
        if request_field(receiver, aliases) and len(node.args) == 1 and not isinstance(node.args[0], ast.Starred):
            if node.func.attr == "get":
                return TEXT
            if node.func.attr in ("getlist", "get_all"):
                return TEXT_LIST
        if node.func.attr == "replace" and len(node.args) == 2:
            old, new = (value_of(part, facts, aliases) for part in node.args)
            original = value_of(receiver, facts, aliases)
            if old == "'" and type(new) is str and "'" not in new and (original is TEXT or original is NO_APOSTROPHE or type(original) is str):
                return NO_APOSTROPHE
        if node.func.attr == "join" and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
            separator = value_of(receiver, facts, aliases)
            items = [value_of(item, facts, aliases) for item in node.args[0].elts]
            if type(separator) is str and all(type(item) is str for item in items) and sum(map(len, items)) + max(0, len(items) - 1) * len(separator) <= 4096:
                return primitive(separator.join(items))
        if node.func.attr == "format":
            template = value_of(receiver, facts, aliases)
            if type(template) is str:
                return positional_format(template, [value_of(item, facts, aliases) for item in node.args])
    if isinstance(node, ast.JoinedStr):
        parts = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                if part.format_spec is not None or part.conversion != -1:
                    return UNKNOWN
                part = part.value
            parts.append(value_of(part, facts, aliases))
        if len(parts) == 3 and type(parts[0]) is str and XPATH_LITERAL.fullmatch(parts[0]) and parts[1] is NO_APOSTROPHE and parts[2] == "']":
            return SAFE_XPATH
        if all(type(part) in (str, int, bool) for part in parts):
            return primitive("".join(map(str, parts)))
    return UNKNOWN


def stores(node):
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            yield child.id
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield child.name
        if isinstance(child, (ast.MatchAs, ast.MatchStar, ast.ExceptHandler)) and child.name:
            yield child.name
        if isinstance(child, ast.MatchMapping) and child.rest:
            yield child.rest
        if isinstance(child, ast.alias):
            yield child.asname or child.name.split(".")[0]


def assignment(node):
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value
    return None


def match_literal(pattern, subject):
    if isinstance(pattern, ast.MatchAs) and pattern.pattern is None and pattern.name is None:
        return True
    if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
        value = pattern.value.value
        return subject == value if type(value) in (str, int) else None
    if isinstance(pattern, ast.MatchOr):
        parts = [match_literal(part, subject) for part in pattern.patterns]
        return any(parts) if None not in parts else None
    return None


def selected_branch(stmt, facts, aliases):
    if isinstance(stmt, ast.If):
        condition = value_of(stmt.test, facts, aliases)
        if type(condition) is bool:
            return stmt.body if condition else stmt.orelse
    if isinstance(stmt, ast.Match):
        subject = value_of(stmt.subject, facts, aliases)
        if type(subject) in (str, int) and all(case.guard is None for case in stmt.cases):
            for case in stmt.cases:
                matches = match_literal(case.pattern, subject)
                if matches is None:
                    return None
                if matches:
                    return case.body
            return []
    return None


def rejects(stmt):
    return isinstance(stmt, ast.If) and not stmt.orelse and isinstance(stmt.body[-1], (ast.Return, ast.Raise))


def merge_values(left, right):
    if type(left) is type(right) and type(left) in (str, int, bool) and left == right:
        return left
    if all(v is NO_APOSTROPHE or (type(v) is str and "'" not in v) for v in (left, right)):
        return NO_APOSTROPHE
    if all(v is TEXT or v is NO_APOSTROPHE or type(v) is str for v in (left, right)):
        return TEXT
    return UNKNOWN


def bind(stmt, facts, aliases):
    if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name) and isinstance(stmt.op, ast.Add):
        name = stmt.target.id
        left, right = facts.get(name, UNKNOWN), value_of(stmt.value, facts, aliases)
        facts[name] = primitive(left + right) if type(left) is type(right) is str else UNKNOWN
        return
    binding = assignment(stmt)
    branch = selected_branch(stmt, facts, aliases)
    writes = set(stores(stmt))
    if isinstance(stmt, ast.If) and branch is None and all(assignment(part) for part in [*stmt.body, *stmt.orelse]):
        alternatives = []
        for body in (stmt.body, stmt.orelse):
            option = facts.copy()
            for part in body:
                bind(part, option, aliases)
            alternatives.append(option)
        for name in writes:
            facts[name] = merge_values(*(option.get(name, UNKNOWN) for option in alternatives))
    elif branch is None:
        for name in writes - ({binding[0]} if binding else set()):
            facts.pop(name, None)
    if binding:
        name, expression = binding
        facts[name] = value_of(expression, facts, aliases)
    elif branch is not None and all(assignment(part) for part in branch):
        for part in branch:
            bind(part, facts, aliases)
    elif branch is not None:
        for name in stores(stmt):
            facts.pop(name, None)
    if rejects(stmt):
        condition = stmt.test
        if (
            isinstance(condition, ast.Compare) and len(condition.ops) == 1
            and isinstance(condition.ops[0], ast.In) and isinstance(condition.left, ast.Constant)
            and condition.left.value == "'" and isinstance(condition.comparators[0], ast.Name)
        ):
            name = condition.comparators[0].id
            if facts.get(name) is TEXT:
                facts[name] = NO_APOSTROPHE


def method(node, name, arity):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == name and len(node.args) == arity and not node.keywords


def import_bindings(stmt):
    if isinstance(stmt, ast.Import):
        return {item.asname or item.name.split(".")[0]: item.name if item.asname else item.name.split(".")[0] for item in stmt.names}
    if isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module:
        return {item.asname or item.name: stmt.module + "." + item.name for item in stmt.names if item.name != "*"}
    return {}


def alias_writes(stmt):
    for node in ast.walk(stmt):
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            base = node
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id in ("setattr", "delattr") and node.args):
            base = node.args[0]
        else:
            continue
        while isinstance(base, (ast.Attribute, ast.Subscript)):
            base = base.value
        if isinstance(base, ast.Name):
            yield base.id


def guarded_https_redirect(arg, previous, aliases):
    if previous and isinstance(previous[-1], ast.Try):
        guard = previous[-1]
        if (len(guard.body) != 2 or guard.orelse or guard.finalbody or not guard.handlers
                or not all(isinstance(handler.body[-1], (ast.Return, ast.Raise)) for handler in guard.handlers)):
            return False
        previous = guard.body
    if len(previous) < 2 or not isinstance(arg, ast.Name) or not rejects(previous[-1]):
        return False
    parsed = assignment(previous[-2])
    test = previous[-1].test
    if not parsed or not isinstance(test, ast.BoolOp) or not isinstance(test.op, ast.Or) or len(test.values) != 2:
        return False
    name, parser = parsed
    if name == arg.id or not isinstance(parser, ast.Call) or len(parser.args) != 1 or parser.keywords:
        return False
    if canonical(parser.func, aliases) not in ("urllib.parse.urlparse", "urllib.parse.urlsplit"):
        return False
    if not isinstance(parser.args[0], ast.Name) or parser.args[0].id != arg.id:
        return False
    checks = set()
    for check in test.values:
        if not isinstance(check, ast.Compare) or len(check.ops) != 1 or not isinstance(check.left, ast.Attribute):
            return False
        if not isinstance(check.left.value, ast.Name) or check.left.value.id != name:
            return False
        field, op, values = check.left.attr, check.ops[0], check.comparators[0]
        if field == "scheme" and isinstance(op, ast.NotEq) and isinstance(values, ast.Constant) and values.value == "https":
            checks.add(field)
        elif field == "netloc" and isinstance(op, ast.NotIn) and isinstance(values, (ast.List, ast.Tuple, ast.Set)):
            if not values.elts or not all(isinstance(el, ast.Constant) and type(el.value) is str and DNS_HOST.fullmatch(el.value) for el in values.elts):
                return False
            checks.add(field)
        else:
            return False
    return checks == {"netloc", "scheme"}


def inside_resolved_root(arg, condition, previous, facts, aliases):
    if len(previous) < 2 or not isinstance(arg, ast.Name) or not method(condition, "is_relative_to", 1):
        return False
    base, candidate = map(assignment, previous[-2:])
    if not base or not candidate or candidate[0] != arg.id:
        return False
    base_name, base_expression = base
    path_expression = candidate[1]
    if base_name == arg.id or not method(base_expression, "resolve", 0) or not method(path_expression, "resolve", 0):
        return False
    constructor = base_expression.func.value
    joined = path_expression.func.value
    shape = (
        isinstance(constructor, ast.Call) and canonical(constructor.func, aliases) == "pathlib.Path"
        and len(constructor.args) == 1 and not constructor.keywords
        and isinstance(constructor.args[0], ast.Constant) and type(constructor.args[0].value) is str
        and isinstance(joined, ast.BinOp) and isinstance(joined.op, ast.Div)
        and isinstance(joined.left, ast.Name) and joined.left.id == base_name
        and isinstance(condition.func.value, ast.Name) and condition.func.value.id == arg.id
        and isinstance(condition.args[0], ast.Name) and condition.args[0].id == base_name
        and not any(isinstance(child, ast.NamedExpr) for child in ast.walk(joined.right))
    )
    if not shape:
        return False
    component_facts = {name: value for name, value in facts.items() if name not in (base_name, arg.id)}
    component = value_of(joined.right, component_facts, aliases)
    return component is TEXT or component is NO_APOSTROPHE or type(component) is str


def literal_interpolations(expression, facts):
    if not isinstance(expression, ast.JoinedStr):
        return []
    replacements = []
    for part in expression.values:
        if not isinstance(part, ast.FormattedValue) or part.conversion != -1 or part.format_spec is not None:
            continue
        item = part.value
        if not isinstance(item, ast.Name) or item.lineno != item.end_lineno:
            continue
        value = facts.get(item.id, UNKNOWN)
        if type(value) in (str, int, bool):
            replacements.append([item.lineno, item.col_offset, item.end_col_offset, ascii(value)])
    return replacements


class Source:
    def __init__(self, filename):
        tree = ast.parse(Path(filename).read_bytes(), filename="<scanned>")
        self.tree = tree
        self.parents = {}
        self.calls = {}
        self.arguments = {}
        self.returns = {}
        self.imports = {}
        for node in ast.walk(tree):
            self.parents.update((child, node) for child in ast.iter_child_nodes(node))
            if isinstance(node, ast.Call):
                self.calls[(node.lineno, node.col_offset + 1)] = node
                for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                    self.arguments.setdefault((arg.lineno, arg.col_offset + 1), []).append(arg)
            if isinstance(node, ast.Return) and node.value is not None:
                value = node.value
                self.returns[(value.lineno, value.col_offset + 1)] = value
        for stmt in tree.body:
            if isinstance(stmt, ast.ImportFrom) and any(item.name == "*" for item in stmt.names):
                self.imports.clear()
            for name in set(stores(stmt)).union(alias_writes(stmt)):
                self.imports.pop(name, None)
            self.imports.update(import_bindings(stmt))

    def before(self, stmt):
        owner = self.parents.get(stmt)
        if owner:
            for _, children in ast.iter_fields(owner):
                if isinstance(children, list) and stmt in children:
                    return owner, children[:children.index(stmt)]
        return owner, []

    def prefix(self, stmt, scope):
        blocks = []
        while stmt is not scope:
            owner, previous = self.before(stmt)
            blocks.append(previous)
            if isinstance(owner, ast.If) or (isinstance(owner, ast.Try) and stmt in owner.body):
                stmt = owner
            else:
                break
        return [stmt for block in reversed(blocks) for stmt in block]

    def hash_factory_used_only_for_hmac(self, call):
        if not call or canonical(call.func, self.imports) != "hashlib.sha1" or call.keywords:
            return False
        statement = self.parents.get(call)
        factory = self.parents.get(statement)
        if not isinstance(statement, ast.Return) or not isinstance(factory, ast.FunctionDef):
            return False
        if self.parents.get(factory) is not self.tree or not factory.name.startswith("_") or factory.decorator_list:
            return False
        body = factory.body[1:] if ast.get_docstring(factory) is not None else factory.body
        parameters = [*factory.args.posonlyargs, *factory.args.args]
        if body != [statement] or len(parameters) != 1 or len(call.args) != 1:
            return False
        if not isinstance(call.args[0], ast.Name) or call.args[0].id != parameters[0].arg:
            return False
        if list(stores(self.tree)).count(factory.name) != 1 or "staticmethod" in set(stores(self.tree)):
            return False

        # Keep the warning when the factory is called or reused anywhere else in the module.
        references = [node for node in ast.walk(self.tree) if isinstance(node, ast.Name) and node.id == factory.name]
        if len(references) != 1:
            return False
        wrapper = self.parents.get(references[0])
        binding = self.parents.get(wrapper)
        owner = self.parents.get(binding)
        if not isinstance(owner, ast.ClassDef) or not isinstance(wrapper, ast.Call):
            return False
        if not isinstance(wrapper.func, ast.Name) or wrapper.func.id != "staticmethod" or wrapper.args != references or wrapper.keywords:
            return False
        if assignment(binding) != ("digest_method", wrapper):
            return False
        class_bindings = [item for stmt in owner.body if (item := assignment(stmt))]
        derivation = [value for name, value in class_bindings if name == "key_derivation"]
        if sum(name == "digest_method" for name, _ in class_bindings) != 1 or len(derivation) != 1:
            return False
        if not isinstance(derivation[0], ast.Constant) or derivation[0].value != "hmac":
            return False

        fields = {"key_derivation", "digest_method"}
        accesses = [node for node in ast.walk(owner) if isinstance(node, ast.Attribute) and node.attr in fields]
        if len(accesses) != 2 or {node.attr for node in accesses} != fields:
            return False
        options = self.parents.get(accesses[0])
        if not isinstance(options, ast.Dict) or set(options.values) != set(accesses):
            return False
        if any(not isinstance(key, ast.Constant) or key.value != value.attr or not isinstance(value.value, ast.Name)
               or value.value.id != "self" for key, value in zip(options.keys, options.values)):
            return False
        keyword = self.parents.get(options)
        serializer = self.parents.get(keyword)
        return (
            isinstance(keyword, ast.keyword) and keyword.arg == "signer_kwargs"
            and isinstance(serializer, ast.Call)
            and canonical(serializer.func, self.imports) == "itsdangerous.URLSafeTimedSerializer"
            and all(kw.arg not in (None, "signer") for kw in serializer.keywords)
        )

    def reason(self, line, column, rule):
        if rule == "srcaudit-python-weak-hashlib":
            return "python-hmac-digest-factory" if self.hash_factory_used_only_for_hmac(self.calls.get((line, column))) else None
        matches = self.arguments.get((line, column), [])
        if rule == "srcaudit-python-flask-html-response" and (line, column) in self.returns:
            matches = [self.returns[(line, column)]]
        if len(matches) != 1:
            return None
        arg = matches[0]
        stmt = self.parents.get(arg)
        while stmt and not isinstance(stmt, ast.stmt):
            if isinstance(stmt, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.IfExp)):
                return None
            stmt = self.parents.get(stmt)
        scope = self.parents.get(stmt)
        while scope and not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = self.parents.get(scope)
        if not scope or any(isinstance(node, (ast.Global, ast.Nonlocal, ast.NamedExpr)) for node in ast.walk(scope)):
            return None
        parameters = {node.arg for node in ast.walk(scope.args) if isinstance(node, ast.arg)}
        local = parameters.union(stores(scope))
        outer = self.parents.get(scope)
        while outer:
            if isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                local.update(node.arg for node in ast.walk(outer.args) if isinstance(node, ast.arg))
                local.update(stores(outer))
            outer = self.parents.get(outer)
        aliases = {name: value for name, value in self.imports.items() if name not in local}
        owner, previous = self.before(stmt)
        prefix = self.prefix(stmt, scope)
        facts = {}
        path_rule = rule == "srcaudit-python-request-file-path"
        interpolations = []
        for entry in prefix:
            writes = set(stores(entry))
            if path_rule and isinstance(arg, ast.Name) and arg.id in writes:
                binding = assignment(entry)
                interpolations = literal_interpolations(binding[1], facts) if binding and binding[0] == arg.id else []
            for name in writes.union(alias_writes(entry)):
                aliases.pop(name, None)
            aliases.update(import_bindings(entry))
            bind(entry, facts, aliases)
        if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "exec"
               for entry in prefix for node in ast.walk(entry)):
            return None
        if path_rule:
            if isinstance(owner, ast.If) and stmt is owner.body[0] and inside_resolved_root(arg, owner.test, self.before(owner)[1], facts, aliases):
                return "python-resolved-root"
            if previous and rejects(previous[-1]) and isinstance(previous[-1].test, ast.UnaryOp) and isinstance(previous[-1].test.op, ast.Not):
                if inside_resolved_root(arg, previous[-1].test.operand, previous[:-1], facts, aliases):
                    return "python-resolved-root"
        value = value_of(arg, facts, aliases)
        if (rule == "srcaudit-python-flask-open-redirect" and (value is TEXT or value is NO_APOSTROPHE)
                and guarded_https_redirect(arg, previous, aliases)):
            return "python-https-allowlist"
        if type(value) in (str, int, bool):
            return "python-constant"
        if rule == "srcaudit-python-lxml-xpath-injection" and value is SAFE_XPATH:
            return "python-xpath-delimiter"
        if path_rule:
            return interpolations or literal_interpolations(arg, facts) or None
        return None


def main():
    result = []
    for file, matches in json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).items():
        try:
            source = Source(file)
            for index, line, column, rule in matches:
                reason = source.reason(line, column, rule)
                if reason:
                    result.append([index, reason])
        except (SyntaxError, ValueError, RecursionError, OSError):
            continue
    print(json.dumps(result))


if __name__ == "__main__":
    main()
