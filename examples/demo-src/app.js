// Synthetic examples for static scanning only. DO NOT run or deploy this file.
const password = "DEMO-ONLY-NOT-A-REAL-CREDENTIAL";
eval(req.query.code);
child_process.exec(req.query.command);
db.query("SELECT * FROM users WHERE id=" + req.query.id);
res.send("<p>" + req.query.name);
fetch(req.query.url);
res.sendFile(req.query.path);
merge(config, req.body);
res.redirect(req.query.next);
const options = { rejectUnauthorized: false };
