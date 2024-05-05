const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const cors = require('cors');
const bodyParser = require('body-parser');


const app = express();
//app.use(express.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));


// Simulación de una base de datos de usuarios
const users = [];


const db = mysql.createConnection({
    host: '45.191.0.164',
    user: 'teknoinsumos2_insumos', // Usuario de MySQL
    password: '}H(eSN2AP7-{', // Contraseña de MySQL
    database: 'teknoinsumos2_insumos' // Nombre de tu base de datos
  });

  // Conectar a la base de datos
db.connect((err) => {
    if (err) {
      console.error('Error al conectar a la base de datos: ' + err.stack);
      return;
    }
    console.log('Conexión exitosa a la base de datos MySQL');
  });

// Secret key para firmar los tokens
const secretKey = '48334';

// Ruta de registro de usuarios
app.post('/api/sign-in', async (req, res) => {
  const { email, password } = req.body;
  let payload = {};
 // Verificar si el usuario ya existe
 db.query('SELECT * FROM psid_employee WHERE email = ?', [email], async (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: 'Error interno del servidor' });
    }

    if (results.length == 0) {
      return res.status(400).json({ message: 'Usuario no registrado' });
    }else{
         payload = {
            data: {
              displayName: results[0].firstname + " " + results[0].lastname,
              photoURL: "assets/images/avatars/Abbott.jpg",
              email: email,
              settings: {
                Layout: {
                  style: ["layout2"],
                  config: {
                    mode: "boxed",
                    scroll: "content"
                  },
                  navbar: {
                    display: true
                  }
                },
                theme: {}
              },
              shortcuts: [
                "apps.calendar",
                "apps.mailbox",
                "apps.contacts"
              ]
            },
            role: 'admin'
          };

          const token = jwt.sign({ email }, secretKey);

          const response = {
            uuid: "token_valid",
            from: "custom-db",
            password: "$2y$10$PNWjp0z3Cc8dRksriddWc.xUnW9/TI1BQkeDu6GVvTn7K4tAFeiCq",
            user: payload,
            access_token: token
          };
         
          res.status(200).json(response);

    }


});


});

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Buscar usuario en la base de datos
  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Credenciales inválidas' });
  }

  // Verificar la contraseña
  if (!(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Credenciales inválidas' });
  }

  // Generar token JWT
  const token = jwt.sign({ username }, secretKey);

  res.status(200).json({ token });
});

// Ruta protegida
app.get('/protected', (req, res) => {
  // Verificar token
  const token = req.headers.authorization.split(' ')[1];
  try {
    jwt.verify(token, secretKey);
    res.status(200).json({ message: 'Acceso autorizado' });
  } catch (error) {
    res.status(401).json({ message: 'Acceso no autorizado' });
  }
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://database:${PORT}`);
});
