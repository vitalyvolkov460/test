const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(cors());
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 5e7 }); 

const JWT_SECRET = 'super-secret-key-123';
const ENCRYPTION_KEY = crypto.scryptSync('my-secret-pass', 'salt', 32);
const IV = Buffer.alloc(16, 0); 

const encrypt = (text) => {
    if (!text) return text;
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
};
const decrypt = (text) => {
    if (!text) return text;
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
        return decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
    } catch { return text; }
};

const db = new sqlite3.Database('./messenger.db');
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT, verified INTEGER, pin TEXT, pfp TEXT, about TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS invites (id INTEGER PRIMARY KEY, sender TEXT, receiver TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS friends (u1 TEXT, u2 TEXT, archived1 INTEGER DEFAULT 0, archived2 INTEGER DEFAULT 0)`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, sender TEXT, receiver TEXT, content TEXT, type TEXT, status TEXT, ts INTEGER, edited INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0)`);
    db.run(`CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, name TEXT, owner TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS group_members (group_id TEXT, username TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS group_invites (id TEXT PRIMARY KEY, sender TEXT, receiver TEXT, group_id TEXT, group_name TEXT)`);
});

const sendEmail = (email, subject, pin) => console.log(`\n📧 [EMAIL TO ${email}] -> ${subject}: Your PIN is ${pin}\n`);
const checkPwd = (p) => /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/.test(p);

app.post('/register', (req, res) => {
    const { email, username, password } = req.body;
    if (!checkPwd(password)) return res.status(400).json({ error: 'Weak password' });
    const pin = Math.floor(100000 + Math.random() * 900000).toString();
    db.run(`INSERT INTO users (username, email, password, verified, pin) VALUES (?, ?, ?, 0, ?)`, 
        [encrypt(username.toLowerCase()), encrypt(email.toLowerCase()), bcrypt.hashSync(password, 8), pin], function(err) {
        if (err) return res.status(400).json({ error: 'Username or Email already in use.' });
        sendEmail(email, "Verify Account", pin);
        res.json({ message: 'Registered. Check console for PIN.' });
    });
});

app.post('/verify', (req, res) => {
    db.get(`SELECT id FROM users WHERE email = ? AND pin = ?`, [encrypt(req.body.email.toLowerCase()), req.body.pin], (err, user) => {
        if (!user) return res.status(400).json({ error: 'Invalid PIN' });
        db.run(`UPDATE users SET verified = 1, pin = NULL WHERE id = ?`, [user.id]);
        res.json({ message: 'Verified' });
    });
});

app.post('/login', (req, res) => {
    db.get(`SELECT * FROM users WHERE email = ?`, [encrypt(req.body.email.toLowerCase())], (err, user) => {
        if (!user || !bcrypt.compareSync(req.body.password, user.password)) return res.status(400).json({ error: 'Invalid credentials' });
        if (!user.verified) return res.status(400).json({ error: 'Unverified' });
        res.json({ token: jwt.sign({ username: decrypt(user.username) }, JWT_SECRET), username: decrypt(user.username) });
    });
});

app.post('/reset-req', (req, res) => {
    const pin = Math.floor(100000 + Math.random() * 900000).toString();
    db.run(`UPDATE users SET pin = ? WHERE email = ?`, [pin, encrypt(req.body.email.toLowerCase())], function() {
        if (this.changes) sendEmail(req.body.email, "Reset", pin);
        res.json({ message: 'Sent' });
    });
});

app.post('/reset', (req, res) => {
    if (!checkPwd(req.body.password)) return res.status(400).json({ error: 'Weak password' });
    db.run(`UPDATE users SET password = ?, pin = NULL WHERE email = ? AND pin = ?`, 
        [bcrypt.hashSync(req.body.password, 8), encrypt(req.body.email.toLowerCase()), req.body.pin], function() {
        if (!this.changes) return res.status(400).json({ error: 'Invalid PIN' });
        res.json({ message: 'Reset' });
    });
});

let usersOnline = {}; 
io.on('connection', (socket) => {
    let myUser = null;
    socket.on('auth', (token) => {
        try {
            myUser = jwt.verify(token, JWT_SECRET).username;
            usersOnline[socket.id] = myUser;
            socket.join(myUser); 
            
            db.all(`SELECT group_id FROM group_members WHERE username = ?`, [encrypt(myUser)], (e, rows) => {
                if (rows) rows.forEach(r => socket.join(r.group_id));
                syncData();
            });
        } catch { socket.emit('error', 'Auth Failed'); }
    });

    const syncData = () => {
        const encMe = encrypt(myUser);
        db.get(`SELECT pfp, about FROM users WHERE username = ?`, [encMe], (e, row) => {
            if(row) socket.emit('profile', { pfp: decrypt(row.pfp), about: decrypt(row.about) });
        });
        db.all(`SELECT * FROM invites WHERE receiver = ?`, [encMe], (e, rows) => {
            socket.emit('invites', rows.map(r => ({ id: r.id, sender: decrypt(r.sender) })));
        });
        db.all(`SELECT * FROM friends WHERE u1 = ? OR u2 = ?`, [encMe, encMe], (e, rows) => {
            socket.emit('friends', rows.map(r => ({ 
                u: r.u1 === encMe ? decrypt(r.u2) : decrypt(r.u1), 
                archived: r.u1 === encMe ? r.archived1 : r.archived2 
            })));
        });
        db.all(`SELECT g.id, g.name FROM groups g JOIN group_members m ON g.id = m.group_id WHERE m.username = ?`, [encMe], (e, rows) => {
            socket.emit('groups', rows.map(r => ({ id: r.id, name: decrypt(r.name) })));
        });
        db.all(`SELECT * FROM group_invites WHERE receiver = ?`, [encMe], (e, rows) => {
            socket.emit('groupInvites', rows.map(r => ({ id: r.id, sender: decrypt(r.sender), groupId: r.group_id, groupName: decrypt(r.group_name) })));
        });
        db.all(`SELECT * FROM messages WHERE sender = ? OR receiver = ? OR receiver IN (SELECT group_id FROM group_members WHERE username = ?) ORDER BY ts ASC`, [encMe, encMe, encMe], (e, rows) => {
            socket.emit('messages', rows.map(r => ({
                id: r.id, sender: decrypt(r.sender), receiver: r.receiver.startsWith('GRP_') ? r.receiver : decrypt(r.receiver),
                content: decrypt(r.content), type: r.type, status: r.status, ts: r.ts, edited: r.edited, deleted: r.deleted
            })));
        });
    };

    socket.on('updateProfile', (data) => {
        db.run(`UPDATE users SET pfp = ?, about = ? WHERE username = ?`, [encrypt(data.pfp), encrypt(data.about), encrypt(myUser)]);
    });

    socket.on('searchUser', (q) => {
        const eq = encrypt(q.toLowerCase());
        db.get(`SELECT username FROM users WHERE username = ? OR email = ?`, [eq, eq], (e, row) => {
            if (row && decrypt(row.username) !== myUser) socket.emit('searchRes', decrypt(row.username));
            else socket.emit('error', 'Not found');
        });
    });

    socket.on('sendInvite', (to) => {
        db.run(`INSERT INTO invites (sender, receiver) VALUES (?, ?)`, [encrypt(myUser), encrypt(to)], () => {
            io.to(to).emit('newInvite');
            socket.emit('success', 'Invite sent');
        });
    });

    socket.on('handleInvite', ({ id, accept, sender }) => {
        db.run(`DELETE FROM invites WHERE id = ?`, [id], () => {
            if (accept) {
                db.run(`INSERT INTO friends (u1, u2) VALUES (?, ?)`, [encrypt(myUser), encrypt(sender)], () => {
                    io.to(sender).emit('syncReq'); 
                    syncData(); 
                });
            } else { syncData(); }
        });
    });

    socket.on('createGroup', (name) => {
        const gid = 'GRP_' + Date.now();
        db.run(`INSERT INTO groups (id, name, owner) VALUES (?, ?, ?)`, [gid, encrypt(name), encrypt(myUser)], () => {
            db.run(`INSERT INTO group_members (group_id, username) VALUES (?, ?)`, [gid, encrypt(myUser)], () => {
                socket.join(gid);
                syncData();
                socket.emit('success', 'Group Created');
            });
        });
    });

    socket.on('sendGroupInvite', ({ to, groupId, groupName }) => {
        const id = Date.now().toString();
        db.run(`INSERT INTO group_invites (id, sender, receiver, group_id, group_name) VALUES (?, ?, ?, ?, ?)`,
            [id, encrypt(myUser), encrypt(to), groupId, encrypt(groupName)], () => {
            io.to(to).emit('newInvite');
            socket.emit('success', 'Group invite sent');
        });
    });

    socket.on('handleGroupInvite', ({ id, accept, groupId }) => {
        db.run(`DELETE FROM group_invites WHERE id = ?`, [id], () => {
            if (accept) {
                db.run(`INSERT INTO group_members (group_id, username) VALUES (?, ?)`, [groupId, encrypt(myUser)], () => {
                    socket.join(groupId);
                    syncData();
                });
            } else { syncData(); }
        });
    });

    socket.on('toggleArchive', (friend) => {
        db.run(`UPDATE friends SET archived1 = CASE WHEN u1 = ? THEN NOT archived1 ELSE archived1 END, archived2 = CASE WHEN u2 = ? THEN NOT archived2 ELSE archived2 END WHERE (u1 = ? AND u2 = ?) OR (u1 = ? AND u2 = ?)`,
            [encrypt(myUser), encrypt(myUser), encrypt(myUser), encrypt(friend), encrypt(friend), encrypt(myUser)], syncData);
    });

    socket.on('sendMsg', (m) => {
        const id = Date.now().toString();
        const isGroup = m.to.startsWith('GRP_');
        const rec = isGroup ? m.to : encrypt(m.to);
        
        db.run(`INSERT INTO messages (id, sender, receiver, content, type, status, ts) VALUES (?, ?, ?, ?, ?, 'sent', ?)`,
            [id, encrypt(myUser), rec, encrypt(m.content), m.type, Date.now()], () => {
            
            const msgObj = { id, sender: myUser, receiver: m.to, content: m.content, type: m.type, status: 'sent', ts: Date.now(), edited: 0, deleted: 0 };
            
            if (isGroup || Object.values(usersOnline).includes(m.to)) {
                db.run(`UPDATE messages SET status = 'delivered' WHERE id = ?`, [id]);
                msgObj.status = 'delivered';
            }
            io.to(m.to).emit('msgUpdate', msgObj);
            if (!isGroup) socket.emit('msgUpdate', msgObj); // Emit to self for direct msgs
        });
    });

    socket.on('markRead', (sender) => {
        if(sender.startsWith('GRP_')) return; 
        db.run(`UPDATE messages SET status = 'read' WHERE sender = ? AND receiver = ? AND status != 'read'`, [encrypt(sender), encrypt(myUser)], function() {
            if (this.changes > 0) io.to(sender).emit('syncReq');
            syncData();
        });
    });

    socket.on('editMsg', ({ id, content }) => {
        db.run(`UPDATE messages SET content = ?, edited = 1 WHERE id = ? AND sender = ?`, [encrypt(content), id, encrypt(myUser)], () => { io.emit('syncReq'); });
    });

    socket.on('deleteMsg', (id) => {
        db.run(`UPDATE messages SET deleted = 1, content = ? WHERE id = ? AND sender = ?`, [encrypt(""), id, encrypt(myUser)], () => { io.emit('syncReq'); });
    });

    socket.on('typing', ({ to, isTyping }) => { io.to(to).emit('isTyping', { user: myUser, isTyping }); });
    socket.on('disconnect', () => delete usersOnline[socket.id]);
});

server.listen(3000, () => console.log('Server running on port 3000'));
