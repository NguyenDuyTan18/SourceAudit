const route = (prefix, registration, body) => prefix + '\n' + registration + ' {\n' + body + '\n});';

export const expressSqlCases = [
  {
    name: 'express-sql-router-renamed-request', ext: 'ts', cwe: 'CWE-89', sink: 'statement',
    vulnerable: route('import { Router } from "express";\nconst router = Router();', 'router.get("/users", (incoming, response) =>',
      '  const id = incoming.query.id;\n  const statement = "SELECT * FROM users WHERE id=" + id;\n  return pool.query(statement);'),
    fixed: route('import { Router } from "express";\nconst router = Router();', 'router.get("/users", (incoming, response) =>',
      '  const id = incoming.query.id;\n  return pool.query("SELECT * FROM users WHERE id=$1", [id]);'),
  },
  {
    name: 'express-sql-middleware-and-config', ext: 'js', cwe: 'CWE-89', sink: 'statement', multiline: true,
    vulnerable: route('const express = require("express");\nconst api = express();', 'api.post("/users", requireSession, function (incoming, response)',
      '  const id = incoming.body.id;\n  const statement = "SELECT * FROM users WHERE id=" + id;\n  return pool.query({\n    text: statement +\n      " ORDER BY id",\n  });'),
    fixed: route('const express = require("express");\nconst api = express();', 'api.post("/users", requireSession, function (incoming, response)',
      '  const id = incoming.body.id;\n  return pool.query({ text: "SELECT * FROM users WHERE id=$1", values: [id] });'),
  },
];
