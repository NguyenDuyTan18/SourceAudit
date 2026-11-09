// Synthetic static-analysis example. Do not execute or deploy.
const userId = req.query.id;
const sql = "SELECT * FROM users WHERE id=" + userId;
db.query(sql);
const script = req.body.code;
eval(script);
res.redirect(req.query.next);
users.findOne(req.body);
const token = Math.random().toString(36);
box.insertAdjacentHTML("beforeend", req.body.html);
