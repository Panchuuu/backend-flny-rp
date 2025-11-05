// 1. Importar las librerías
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');


const app = express();

let serverStatus = { online: false, players: 0, maxPlayers: 'N/A' };

// 3. Middlewares
app.use(cors());
app.use(express.json());

const PRODUCT_TO_ROLE_MAP = {
    'vip_bronze': process.env.VIP_BRONCE_ROLE_ID,
    'vip_silver': process.env.VIP_PLATA_ROLE_ID,
    'vip_gold':   process.env.VIP_ORO_ROLE_ID
};

console.log("CLIENT ID:", process.env.DISCORD_CLIENT_ID);
console.log("CLIENT SECRET:", process.env.DISCORD_CLIENT_SECRET);

// 4. Conectar y configurar la base de datos
const db = new sqlite3.Database('./flaitesnytest.db', (err) => {
    if (err) { return console.error('Error al conectar con la base de datos:', err.message); }
    
    console.log('Conectado a la base de datos SQLite "flaitesnytest.db".');
    
    db.serialize(() => {
        // Tabla de usuarios
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            discord_id TEXT UNIQUE NOT NULL,
            fivem_license TEXT,
            avatar TEXT,
            role TEXT DEFAULT 'user' NOT NULL
        )`);

        // Tabla de cupones (Esta estructura es correcta, la mantenemos)
        db.run(`CREATE TABLE IF NOT EXISTS coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, type TEXT NOT NULL,
            value INTEGER NOT NULL, is_active INTEGER DEFAULT 1, expiry_date TEXT
        )`, () => {
            const couponsToSeed = [{ code: 'FLAITES10', type: 'percent', value: 10 }, { code: 'BIENVENIDO5K', type: 'fixed', value: 5000 }];
            const sql = `INSERT OR IGNORE INTO coupons (code, type, value) VALUES (?, ?, ?)`;
            couponsToSeed.forEach(c => db.run(sql, [c.code, c.type, c.value]));
        });

        // --- Tabla de Órdenes ---
        db.run(`CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT NOT NULL,
            recipient_username TEXT, paypal_order_id TEXT UNIQUE NOT NULL,
            product_name TEXT NOT NULL, quantity INTEGER NOT NULL,
            total_paid_usd REAL NOT NULL, purchase_date DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // --- Tabla de Notificaciones ---
        db.run(`CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_user_id INTEGER NOT NULL,
            sender_username TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (recipient_user_id) REFERENCES users (id)
        )`);

        // --- Tablas de Tienda (ESTRUCTURA CORREGIDA) ---
        
        // 1. Crear tabla de Categorías
        db.run(`CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            sort_order INTEGER DEFAULT 0
        )`, () => {
            // 2. DESPUÉS de crear categorías, insertar la categoría
            db.run(`INSERT OR IGNORE INTO categories (id, name, sort_order) VALUES (1, 'Membresías VIP', 1)`);
        });

        // 3. Crear tabla de Productos
        db.run(`CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,
            product_key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            price INTEGER NOT NULL,
            image_url TEXT NOT NULL,
            benefits_list TEXT,
            border_color TEXT DEFAULT 'border-secondary',
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (category_id) REFERENCES categories (id)
        )`, () => {
            // 4. DESPUÉS de crear productos, insertar los productos
            db.run(`INSERT OR IGNORE INTO products (category_id, product_key, name, description, price, image_url, benefits_list, border_color) 
                    VALUES (
                        1, 'vip_bronze', '🗽 VIP Bronce', 'Obtén beneficios iniciales y apoya al servidor.', 5000, 'assets/img/flny-vip-bronce.png', 
                        '✅ Fila de prioridad en el servidor.\n✅ Acceso a vehículos exclusivos (Nivel 1).\n✅ Salario aumentado en un 10%.\n✅ Kit de bienvenida mensual.', 
                        'border-warning'
                    )`);

            db.run(`INSERT OR IGNORE INTO products (category_id, product_key, name, description, price, image_url, benefits_list, border_color) 
                    VALUES (
                        1, 'vip_silver', '🗽 VIP Plata', 'Incluye todos los beneficios de Bronce y más.', 10000, 'assets/img/flny-vip-plata.png', 
                        '✅ Todos los beneficios de Bronce.\n✅ Acceso a vehículos exclusivos (Nivel 2).\n✅ Customización de personaje avanzada.\n✅ Acceso a canal de Discord para VIPs.', 
                        'border-primary'
                    )`);

            db.run(`INSERT OR IGNORE INTO products (category_id, product_key, name, description, price, image_url, benefits_list, border_color) 
                    VALUES (
                        1, 'vip_gold', '🗽 VIP Oro', 'El paquete definitivo para la experiencia completa.', 15000, 'assets/img/flny-vip-oro.png', 
                        '✅ Todos los beneficios de Plata.\n✅ Acceso a todas las skins de armas.\n✅ Posibilidad de crear tu propia banda.\n✅ Soporte prioritario en Discord.', 
                        'border-warning'
                    )`);
        });
    });
});

function verifyAdmin(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Bearer <token>
    if (!token) return res.status(401).json({ message: 'Acceso denegado. No se proveyó un token.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token no es válido.' });

        // Verificamos que el usuario tenga el rol de 'admin'
        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'Acceso prohibido. Se requiere rol de administrador.' });
        }
        
        req.user = user; // Guardamos los datos del usuario en la petición para uso futuro
        next(); // Si todo está bien, continuamos a la ruta solicitada
    });
}

function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Acceso denegado. No se proveyó un token.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token no es válido.' });
        req.user = user; // Guardamos los datos del token en la petición
        next();
    });
}

// --- RUTAS DE LA API ---

app.get('/', (req, res) => res.send('¡El backend de Flaites NY está funcionando!'));

app.get('/users', verifyAdmin, (req, res) => {
    const sql = "SELECT id, username, discord_id, fivem_license, avatar, role FROM users";
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ "error": err.message });
        res.status(200).json(rows);
    });
});

// Rutas de autenticación con Discord
app.get('/auth/discord', (req, res) => {
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A3002%2Fauth%2Fdiscord%2Fcallback&response_type=code&scope=identify`;
    res.redirect(discordAuthUrl);
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send("Error: No se recibió el código de autorización.");

    try {
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: process.env.DISCORD_CLIENT_ID, client_secret: process.env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code', code,
            redirect_uri: `${process.env.BACKEND_URL}/auth/discord/callback`
        }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

        const { access_token } = tokenResponse.data;
        const userResponse = await axios.get('https://discord.com/api/users/@me', { headers: { 'Authorization': `Bearer ${access_token}` } });
        const discordUser = userResponse.data;

        db.get('SELECT * FROM users WHERE discord_id = ?', [discordUser.id], (err, user) => {
            if (err) return res.status(500).send("Error del servidor");
            if (user) {
                const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
                res.redirect(`${process.env.FRONTEND_URL}/index.html?token=${token}`);
            } else {
                const avatarUrl = `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`;
                res.redirect(`${process.env.FRONTEND_URL}/vincular.html?discordId=${discordUser.id}&username=${discordUser.username}&avatar=${avatarUrl}`);
            }
        });
    } catch (error) {
        console.error("Error en el callback de Discord:", error.response ? error.response.data : error.message);
        res.status(500).send("Error al autenticar con Discord.");
    }
});

app.post('/complete-registration', (req, res) => {
    const { discordId, username, avatar, fivemLicense } = req.body;
    if (!discordId || !username || !fivemLicense) return res.status(400).json({ message: 'Faltan datos.' });

    const sql = `INSERT INTO users (discord_id, username, avatar, fivem_license) VALUES (?, ?, ?, ?)`;
    db.run(sql, [discordId, username, avatar, fivemLicense], function(err) {
        if (err) { return res.status(500).json({ message: 'Error al crear la cuenta.' }); }
        db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, newUser) => {
            const token = jwt.sign({ id: newUser.id, username: newUser.username, role: newUser.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
            res.status(201).json({ message: '¡Cuenta vinculada con éxito!', token: token });
        });
    });
});

// Rutas de Administración
app.post('/admin/users/set-role', verifyAdmin, (req, res) => {
    const { userId, newRole } = req.body;

    if (!userId || !newRole) {
        return res.status(400).json({ message: 'Se requiere userId y newRole.' });
    }
    if (newRole !== 'admin' && newRole !== 'user') {
        return res.status(400).json({ message: 'El rol solo puede ser "admin" o "user".' });
    }

    const sql = `UPDATE users SET role = ? WHERE id = ?`;
    db.run(sql, [newRole, userId], function(err) {
        if (err) { return res.status(500).json({ message: 'Error en la base de datos.' }); }
        res.status(200).json({ message: `Rol del usuario actualizado a ${newRole}.` });
    });
});

app.get('/admin/orders', verifyAdmin, (req, res) => {
    const sql = "SELECT * FROM orders ORDER BY purchase_date DESC";
    db.all(sql, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ "error": err.message });
        }
        const formattedOrders = rows.map(order => ({
            ...order,
            purchase_date: order.purchase_date + 'Z'
        }));
        res.status(200).json(formattedOrders);
    });
});

app.get('/admin/coupons', verifyAdmin, (req, res) => {
    const sql = "SELECT * FROM coupons ORDER BY id DESC";
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ "error": err.message });
        res.status(200).json(rows);
    });
});

// Crear un nuevo cupón
app.post('/admin/coupons', verifyAdmin, (req, res) => {
    const { code, type, value, expiry_date } = req.body; // Recibimos la nueva fecha
    if (!code || !type || !value) {
        return res.status(400).json({ message: 'Los campos código, tipo y valor son requeridos.' });
    }

    const sql = `INSERT INTO coupons (code, type, value, expiry_date) VALUES (?, ?, ?, ?)`;
    // Si la fecha no se envía, se guardará como NULL (sin vencimiento)
    db.run(sql, [code.toUpperCase(), type, value, expiry_date || null], function(err) {
        if (err) {
            if (err.code === 'SQLITE_CONSTRAINT') {
                return res.status(409).json({ message: 'Ese código de cupón ya existe.' });
            }
            return res.status(500).json({ message: 'Error en la base de datos.' });
        }
        res.status(201).json({ message: 'Cupón creado con éxito.' });
    });
});

// Activar o desactivar un cupón
app.post('/admin/coupons/toggle', verifyAdmin, (req, res) => {
    const { id, currentStatus } = req.body;
    const newStatus = currentStatus === 1 ? 0 : 1;

    const sql = `UPDATE coupons SET is_active = ? WHERE id = ?`;
    db.run(sql, [newStatus, id], function(err) {
        if (err) { return res.status(500).json({ message: 'Error en la base de datos.' }); }
        res.status(200).json({ message: 'Estado del cupón actualizado.' });
    });
});


app.delete('/admin/coupons/:id', verifyAdmin, (req, res) => {
    const { id } = req.params; 

    const sql = 'DELETE FROM coupons WHERE id = ?';
    db.run(sql, id, function(err) {
        if (err) {
            return res.status(500).json({ message: 'Error en la base de datos.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Cupón no encontrado.' });
        }
        res.status(200).json({ message: 'Cupón eliminado con éxito.' });
    });
});

app.get('/admin/stats', verifyAdmin, (req, res) => {
    const promises = [
        new Promise((resolve, reject) => db.get("SELECT COUNT(*) as count FROM users", (err, row) => err ? reject(err) : resolve(row.count))),
        new Promise((resolve, reject) => db.get("SELECT COUNT(*) as count FROM orders", (err, row) => err ? reject(err) : resolve(row.count))),
        new Promise((resolve, reject) => db.get("SELECT SUM(total_paid_usd) as sum FROM orders", (err, row) => err ? reject(err) : resolve(row.sum || 0))),
        new Promise((resolve, reject) => db.all("SELECT product_name, COUNT(*) as sales FROM orders GROUP BY product_name ORDER BY sales DESC LIMIT 3", (err, rows) => err ? reject(err) : resolve(rows)))
    ];

    Promise.all(promises)
        .then(([totalUsers, totalOrders, totalRevenue, topProducts]) => {
            res.status(200).json({
                totalUsers,
                totalOrders,
                totalRevenue,
                topProducts
            });
        })
        .catch(err => {
            res.status(500).json({ message: "Error al obtener las estadísticas.", error: err.message });
        });
}); 

app.get('/api/verify', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No se proveyó un token.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token no es válido.' });
        res.status(200).json(user);
    });
});

app.get('/api/products', (req, res) => {
    const sql = `
        SELECT 
            c.name as category_name,
            p.product_key,
            p.name,
            p.description,
            p.price,
            p.image_url,
            p.benefits_list,
            p.border_color
        FROM products p
        JOIN categories c ON p.category_id = c.id
        WHERE p.is_active = 1
        ORDER BY c.sort_order, p.price
    `;
    
    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error("Error al obtener productos:", err.message);
            return res.status(500).json({ "error": err.message });
        }
        
        // Agrupar productos por categoría
        const categories = {};
        rows.forEach(row => {
            const catName = row.category_name;
            if (!categories[catName]) {
                categories[catName] = [];
            }
            categories[catName].push(row);
        });

        res.status(200).json(categories);
    });
});

// Rutas de la tienda
app.post('/validate-coupon', (req, res) => {
    const { code } = req.body;

    if (!code) {
        return res.status(400).json({ message: 'Se requiere un código de cupón.' });
    }

    const sql = "SELECT * FROM coupons WHERE code = ? AND is_active = 1";
    
    db.get(sql, [code.toUpperCase()], (err, coupon) => {
        if (err) {
            console.error("Error al validar cupón:", err.message);
            return res.status(500).json({ message: 'Error al consultar la base de datos.' });
        }
        
        if (coupon) {
            // ¡NUEVA VERIFICACIÓN!
            const today = new Date();
            const expiryDate = new Date(coupon.expiry_date);
            
            // Ponemos la hora a cero para comparar solo las fechas
            today.setHours(0, 0, 0, 0); 
            
            if (coupon.expiry_date && expiryDate < today) {
                // Si la fecha de vencimiento ya pasó, el cupón no es válido
                return res.status(404).json({ message: 'Este cupón ha expirado.' });
            }
            
            // Si no ha expirado, lo devolvemos
            res.status(200).json(coupon);
        } else {
            res.status(404).json({ message: 'El cupón no es válido o está inactivo.' });
        }
    });
});

app.get('/api/notifications', verifyToken, (req, res) => {
    const userId = req.user.id;
    const sql = "SELECT * FROM notifications WHERE recipient_user_id = ? ORDER BY created_at DESC LIMIT 10";
    db.all(sql, [userId], (err, rows) => {
        if (err) return res.status(500).json({ "error": err.message });
        res.status(200).json(rows);
    });
});
app.post('/api/notifications/mark-read', verifyToken, (req, res) => {
    const userId = req.user.id;
    const sql = "UPDATE notifications SET is_read = 1 WHERE recipient_user_id = ? AND is_read = 0";
    db.run(sql, [userId], function(err) {
        if (err) return res.status(500).json({ "error": err.message });
        res.status(200).json({ message: 'Notificaciones marcadas como leídas.' });
    });
});

app.get('/api/profile', verifyToken, async (req, res) => {
    const username = req.user.username; // Obtenemos el username del token verificado

    try {
        // 1. Obtener datos del usuario de nuestra base de datos
        const userDetailsPromise = new Promise((resolve, reject) => {
            db.get("SELECT username, discord_id, fivem_license, avatar FROM users WHERE username = ?", [username], (err, row) => err ? reject(err) : resolve(row));
        });

        // 2. Obtener historial de compras de nuestra base de datos
        const purchaseHistoryPromise = new Promise((resolve, reject) => {
            db.all("SELECT * FROM orders WHERE username = ? ORDER BY purchase_date DESC", [username], (err, rows) => err ? reject(err) : resolve(rows));
        });

        // 3. Obtener roles actuales desde la API de Discord
        const discordRolesPromise = (async () => {
            const userDetails = await userDetailsPromise; // Necesitamos el discord_id primero
            if (!userDetails) return [];
            
            const guildId = process.env.DISCORD_GUILD_ID;
            const botToken = process.env.DISCORD_BOT_TOKEN;
            const url = `https://discord.com/api/v10/guilds/${guildId}/members/${userDetails.discord_id}`;
            
            try {
                const response = await axios.get(url, { headers: { 'Authorization': `Bot ${botToken}` } });
                return response.data.roles; // Devuelve un array de IDs de roles
            } catch (error) {
                console.error("Error al obtener roles de Discord para el perfil:", error.response?.data);
                return []; // Si el usuario no está en el servidor, devuelve un array vacío
            }
        })();

        // Ejecutar todas las promesas en paralelo
        const [userDetails, purchaseHistory, activeDiscordRoles] = await Promise.all([userDetailsPromise, purchaseHistoryPromise, discordRolesPromise]);

        if (!userDetails) {
            return res.status(404).json({ message: "Usuario no encontrado." });
        }

        const formattedPurchaseHistory = purchaseHistory.map(order => ({
            ...order,
            purchase_date: order.purchase_date + 'Z'
        }));

        res.status(200).json({
            userDetails,
            purchaseHistory: formattedPurchaseHistory, // Enviamos el historial con la fecha corregida
            activeDiscordRoles
        });
    } catch (error) {
        res.status(500).json({ message: "Error al obtener los datos del perfil." });
    }
});

app.get('/api/users/search', verifyToken, (req, res) => {
    const searchTerm = req.query.term;
    const currentUser = req.user.username; // Obtenemos el usuario que realiza la búsqueda desde el token

    if (!searchTerm || searchTerm.length < 2) {
        return res.json([]);
    }

    const sql = `
        SELECT username, avatar 
        FROM users 
        WHERE username LIKE ? AND username != ? 
        LIMIT 10
    `;
    
    // Le añadimos los comodines '%' al término de búsqueda
    const searchValue = `%${searchTerm}%`;

    db.all(sql, [searchValue, currentUser], (err, rows) => {
        if (err) {
            console.error("Error al buscar usuarios:", err.message);
            return res.status(500).json({ message: "Error en la base de datos." });
        }
        res.status(200).json(rows);
    });
});

app.post('/create-test-order', async (req, res) => {
    const { cart, currentUser } = req.body;
    if (!cart || !currentUser || cart.length === 0) {
        return res.status(400).json({ message: 'Faltan datos.' });
    }

    // Buscamos al comprador una sola vez.
    const buyer = await new Promise(resolve => {
        db.get('SELECT id, discord_id FROM users WHERE username = ?', [currentUser], (err, row) => resolve(row));
    });

    if (!buyer) {
        return res.status(500).json({ message: 'No se pudo encontrar al usuario comprador.' });
    }

    for (const item of cart) {
        const fakePaypalId = `TEST_${Date.now()}_${Math.random()}`;
        const totalUSD = (item.price * item.quantity / 950).toFixed(2);
        
        db.run(`INSERT INTO orders (username, recipient_username, paypal_order_id, product_name, quantity, total_paid_usd) VALUES (?, ?, ?, ?, ?, ?)`, 
            [currentUser, item.recipient || null, fakePaypalId, item.name, item.quantity, totalUSD]);
        
        const roleIdToGrant = PRODUCT_TO_ROLE_MAP[item.id];
        
        if (roleIdToGrant) {
            let targetDiscordId = buyer.discord_id; // Por defecto, el rol es para el comprador.

            if (item.recipient) {
                // Si hay un destinatario (es un regalo)...
                const recipientUser = await new Promise(resolve => {
                    db.get('SELECT id, discord_id FROM users WHERE username = ?', [item.recipient], (err, row) => resolve(row));
                });

                if (recipientUser) {
                    // Si encontramos al destinatario, actualizamos el ID de Discord para el rol.
                    targetDiscordId = recipientUser.discord_id;
                    
                    // --- LÓGICA DE NOTIFICACIÓN CORREGIDA ---
                    const message = `¡Felicidades! Has recibido "${item.name}" de parte de ${currentUser}.`;
                    // Usamos recipientUser.id, que sabemos que es correcto.
                    db.run(`INSERT INTO notifications (recipient_user_id, sender_username, message) VALUES (?, ?, ?)`, 
                        [recipientUser.id, currentUser, message]);
                    
                } else {
                    console.log(`Destinatario del regalo "${item.recipient}" no encontrado. No se asignará rol ni se creará notificación.`);
                    continue; // Pasamos al siguiente item del carrito.
                }
            }
            // Asignamos el rol al ID de Discord correcto (sea el comprador o el destinatario).
            await grantDiscordRole(targetDiscordId, roleIdToGrant);
        }
    }
    
    res.status(201).json({ message: 'Orden de prueba creada. Verificación de rol iniciada.' });
});

// Lógica del estado del servidor FiveM
async function fetchServerStatus() {
    try {
        const playersResponse = await axios.get(`http://${process.env.FIVEM_SERVER_IP}:${process.env.FIVEM_SERVER_PORT}/players.json`);
        const infoResponse = await axios.get(`http://${process.env.FIVEM_SERVER_IP}:${process.env.FIVEM_SERVER_PORT}/info.json`);
        serverStatus = {
            online: true,
            players: playersResponse.data.length,
            maxPlayers: infoResponse.data.vars.sv_maxClients
        };
    } catch (error) {
        serverStatus = { online: false, players: 0, maxPlayers: 'N/A' };
    }
}

async function grantDiscordRole(discordUserId, roleId) {
    const guildId = process.env.DISCORD_GUILD_ID;
    const botToken = process.env.DISCORD_BOT_TOKEN;
    const url = `https://discord.com/api/v10/guilds/${guildId}/members/${discordUserId}/roles/${roleId}`;

    try {
        await axios.put(url, {}, { // Es una petición PUT sin cuerpo
            headers: {
                'Authorization': `Bot ${botToken}`
            }
        });
        console.log(`Rol ${roleId} asignado a ${discordUserId} en el servidor ${guildId}`);
        return true;
    } catch (error) {
        console.error("Error al asignar rol de Discord:", error.response ? error.response.data : error.message);
        return false;
    }
}

fetchServerStatus();
setInterval(fetchServerStatus, 30000);

app.get('/server-status', (req, res) => res.status(200).json(serverStatus));

// Iniciar servidor
const port = 3002;
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});