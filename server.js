const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const tls = require('tls');
const path = require('path');
const session = require('express-session');
const cron = require('node-cron');
const ExcelJS = require('exceljs');

const app = express();
const PORT = 3000;
const ADMIN_PASSWORD = 'admin';

const DB_PATH = path.join(__dirname, 'ssl_manager.db');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'chuoi_bi_mat_de_ma_hoa_session',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600000 }
}));

const requireLogin = (req, res, next) => {
    if (req.session && req.session.isAdmin) next();
    else res.status(401).json({ error: 'Chưa đăng nhập' });
};

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Error:', err.message);
    } else {
        console.log(DB_PATH);
        db.run(`CREATE TABLE IF NOT EXISTS websites (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT UNIQUE NOT NULL,
            expiry_date TEXT,
            days_remaining INTEGER,
            provider    TEXT,
            last_checked TEXT,
            is_vnpt     INTEGER DEFAULT 0
        )`);
    }
});

// Đọc provider, fallback qua nhiều field
function extractProvider(cert) {
    if (!cert || !cert.issuer) return 'Chưa xác định';
    const issuer = cert.issuer;
    // Ưu tiên: O (Organization) → CN (Common Name) → fallback
    return issuer.O || issuer.CN || 'Chưa xác định';
}

function getSSLDetails(domain) {
    return new Promise((resolve) => {
        const socket = tls.connect(
            { servername: domain, host: domain, port: 443, rejectUnauthorized: false, timeout: 7000 },
            () => {
                const cert = socket.getPeerCertificate(true); // true = full chain
                socket.end();

                if (!cert || Object.keys(cert).length === 0) {
                    return resolve({ expiry_date: 'Không tìm thấy SSL', days_remaining: -999, provider: 'Chưa xác định' });
                }

                const provider = extractProvider(cert);
                const expiryDate = new Date(cert.valid_to);
                const daysRemaining = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));

                resolve({
                    expiry_date: expiryDate.toLocaleDateString('vi-VN'),
                    days_remaining: daysRemaining,
                    provider: provider
                });
            }
        );
        socket.on('error', () => {
            socket.destroy();
            resolve({ expiry_date: 'Lỗi kết nối', days_remaining: -999, provider: 'Chưa xác định' });
        });
        socket.setTimeout(7000, () => {
            socket.destroy();
            resolve({ expiry_date: 'Timeout', days_remaining: -999, provider: 'Chưa xác định' });
        });
    });
}

// scan + update db
async function scanAndUpdate(id, domain) {
    const sslInfo = await getSSLDetails(domain);
    const now = new Date().toLocaleString('vi-VN');
    return new Promise((resolve, reject) => {
        db.run(
            `UPDATE websites SET expiry_date = ?, days_remaining = ?, provider = ?, last_checked = ? WHERE id = ?`,
            [sslInfo.expiry_date, sslInfo.days_remaining, sslInfo.provider, now, id],
            (err) => { if (err) reject(err); else resolve(); }
        );
    });
}

// Chạy tối đa 10 scan song song, tránh flood
async function scanAll() {
    const rows = await new Promise((resolve, reject) =>
        db.all(`SELECT id, domain FROM websites`, [], (err, r) => err ? reject(err) : resolve(r))
    );
    const limit = 10;
    for (let i = 0; i < rows.length; i += limit) {
        await Promise.all(rows.slice(i, i + limit).map(r => scanAndUpdate(r.id, r.domain)));
    }
    console.log(`[Cron] Đã quét xong ${rows.length} domain`);
}

// Tự động scan lúc 2 giờ sáng mỗi ngày
cron.schedule('0 2 * * *', () => {
    console.log('[Cron] Bắt đầu scan định kỳ...');
    scanAll();
});

// log 
app.post('/api/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Sai mật khẩu' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

//screen 
app.get('/api/websites', requireLogin, (req, res) => {
    db.all(
        `SELECT id, domain, expiry_date, days_remaining, last_checked, provider, is_vnpt
         FROM websites ORDER BY id DESC`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

app.get('/api/websites/alerts', requireLogin, async (req, res) => {
    try {
        const rows = await new Promise((resolve, reject) => {
            db.all(`SELECT id, domain FROM websites`, [], (err, r) => {
                if (err) reject(err); else resolve(r);
            });
        });

        await Promise.all(rows.map(r => scanAndUpdate(r.id, r.domain)));

        const alerts = await new Promise((resolve, reject) => {
            db.all(
                `SELECT id, domain, expiry_date, days_remaining, provider, last_checked, is_vnpt
                 FROM websites
                 WHERE days_remaining != -999 AND days_remaining <= 30
                 ORDER BY days_remaining ASC`,
                [],
                (err, r) => { if (err) reject(err); else resolve(r); }
            );
        });

        res.json(alerts);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/websites', requireLogin, async (req, res) => {
    const { domain, is_vnpt } = req.body;
    if (!domain) return res.status(400).json({ error: 'Trống tên miền' });

    const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].trim();

    const existing = await new Promise((resolve) => {
        db.get(`SELECT id FROM websites WHERE domain = ?`, [cleanDomain], (err, row) => resolve(row));
    });
    if (existing) return res.status(400).json({ error: `Tên miền "${cleanDomain}" đã tồn tại trong hệ thống` });

    const sslInfo = await getSSLDetails(cleanDomain);
    const now = new Date().toLocaleString('vi-VN');

    db.run(
        `INSERT INTO websites (domain, expiry_date, days_remaining, provider, last_checked, is_vnpt) VALUES (?, ?, ?, ?, ?, ?)`,
        [cleanDomain, sslInfo.expiry_date, sslInfo.days_remaining, sslInfo.provider, now, is_vnpt ? 1 : 0],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, id: this.lastID });
        }
    );
});

app.delete('/api/websites/:id', requireLogin, (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'ID không hợp lệ' });

    db.run(`DELETE FROM websites WHERE id = ?`, [id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Không tìm thấy website để xóa' });
        res.json({ success: true });
    });
});

app.patch('/api/websites/:id/vnpt', requireLogin, (req, res) => {
    const id = parseInt(req.params.id);
    const { is_vnpt } = req.body; // 0 hoặc 1
    if (isNaN(id)) return res.status(400).json({ error: 'ID không hợp lệ' });

    db.run(`UPDATE websites SET is_vnpt = ? WHERE id = ?`, [is_vnpt ? 1 : 0, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Không tìm thấy website' });
        res.json({ success: true });
    });
});

app.post('/api/websites/scan-all', requireLogin, async (req, res) => {
    try {
        const rows = await new Promise((resolve, reject) => {
            db.all(`SELECT id, domain FROM websites`, [], (err, r) => {
                if (err) reject(err); else resolve(r);
            });
        });
        await Promise.all(rows.map(r => scanAndUpdate(r.id, r.domain)));
        res.json({ success: true, message: `Đã quét xong ${rows.length} website.` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/export', requireLogin, async (req, res) => {
    const rows = await new Promise((resolve, reject) =>
        db.all(`SELECT domain, provider, is_vnpt, expiry_date, days_remaining, last_checked FROM websites ORDER BY days_remaining ASC`, [], (err, r) => err ? reject(err) : resolve(r))
    );

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Danh sách SSL');

    sheet.columns = [
        { header: 'Tên miền',          key: 'domain',         width: 30 },
        { header: 'Nhà cung cấp',      key: 'provider',       width: 25 },
        { header: 'VNPT cấp?',         key: 'is_vnpt',        width: 12 },
        { header: 'Ngày hết hạn',      key: 'expiry_date',    width: 15 },
        { header: 'Còn lại (ngày)',    key: 'days_remaining',  width: 15 },
        { header: 'Lần cuối kiểm tra', key: 'last_checked',   width: 20 },
    ];

    rows.forEach(r => sheet.addRow({
        ...r,
        is_vnpt: r.is_vnpt ? 'VNPT cấp' : 'Không phải'
    }));

    // Tô đỏ những dòng còn dưới 30 ngày
    sheet.eachRow((row, i) => {
        if (i === 1) return; // bỏ qua header
        const days = row.getCell('days_remaining').value;
        if (days !== -999 && days <= 30) {
            row.eachCell(cell => {
                cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFE0E0' } };
            });
        }
    });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="ssl-report-${Date.now()}.xlsx"`);
    await workbook.xlsx.write(res);
    res.end();
});

app.get('/', (req, res) => {
    if (req.session && req.session.isAdmin) res.sendFile(path.join(__dirname, 'index.html'));
    else res.sendFile(path.join(__dirname, 'login.html'));
});

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));