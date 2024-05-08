const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const cors = require('cors');
const bodyParser = require('body-parser');
const saltRounds = 10; 


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


function generarHash(password) {
  return new Promise((resolve, reject) => {
    bcrypt.hash(password, saltRounds, (err, hash) => {
      if (err) {
        reject(err);
      } else {
        resolve(hash);
      }
    });
  });
}

// Ruta de registro de usuarios
app.post('/api/sign-in', async (req, res) => {
  const { email, password } = req.body;
  let payload = {};

  
//$2y$10$uz24GabUM0f8.9/8/hxtPeOUmt9AsF2IQY.4itrPPF3f/9L52ZyKS
  const password1 = 'admin';
  try {
    const hash = await generarHash(password1);
    console.log('Hash bcrypt:', hash);
  } catch (err) {
    console.error('Error al generar el hash:', err);
  }

  // Verificar si el usuario ya existe
  db.query('SELECT * FROM psid_employee WHERE email = ?', [email], async (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: 'Error interno del servidor' });
    }

    if (results.length == 0) {
      return res.status(400).json({ message: 'Usuario no registrado' });
    } else {
      // Verificar la contraseña
      const user = results[0];
      const isPasswordValid = await bcrypt.compare(password, user.passwd);

      if (!isPasswordValid) {
        return res.status(400).json({ message: 'Contraseña incorrecta' });
      }

      payload = {
        data: {
          displayName: user.firstname + " " + user.lastname,
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

      const expiresIn = '30m'; // El token expirará en 30 min
      const token = jwt.sign({ payload }, secretKey, { expiresIn });

      const response = {
        uuid: "token_valid",
        from: "custom-db",
        password: isPasswordValid, // No recomendado enviar la contraseña en la respuesta
        user: payload,
        access_token: token
      };

      res.status(200).json(response);
    }
  });
});

app.post('/api/register', async (req, res) => {
  const { email, password, displayName } = req.body;

  // Verificar si el usuario ya está registrado
  db.query('SELECT * FROM psid_employee WHERE email = ?', [email], async (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: 'Error interno del servidor' });
    }

    if (results.length > 0) {
      return res.status(400).json({ message: 'El usuario ya está registrado' });
    } else {
      // Crear un nuevo usuario
      try {
        const hash = await generarHash(password);
        console.log('Hash bcrypt:', hash);

        // Insertar el nuevo usuario en la base de datos
        db.query('INSERT INTO psid_employee (lastname, email, passwd) VALUES (?, ?, ?)', [displayName,email, hash], (error, results) => {
          if (error) {
            console.error(error);
            return res.status(500).json({ message: 'Error al registrar el usuario' });
          }

          // Si el registro es exitoso, devolver un mensaje de éxito
          res.status(200).json({ message: 'Usuario registrado exitosamente' });
        });
      } catch (err) {
        console.error('Error al generar el hash:', err);
        return res.status(500).json({ message: 'Error al registrar el usuario' });
      }
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
app.get('/api/user', (req, res) => {
  // Verificar token
  const token = req.headers.authorization.split(' ')[1];
  try {
    jwt.verify(token, secretKey);
    const decoded = jwt.decode(token);
    console.log(decoded.payload);
    res.status(200).json(decoded.payload);
  } catch (error) {
    res.status(401).json({ message: 'Acceso no autorizado' });
  }
});

// Ruta protegida
app.post('/api/list/product', (req, res) => {
  // Verificar token
  const token = req.headers.authorization.split(' ')[1];
  try {
    jwt.verify(token, secretKey);
    const decoded = jwt.decode(token);
    let ids = [];

    db.query('SELECT * FROM psid_product ',  async (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ message: 'Error interno del servidor' });
      }
  
      if (results.length > 0) {
        results.forEach((row) => {
          ids.push( {"id":row["id_product"] });
        });
      }

      res.status(200).json(ids);

  });

  } catch (error) {
    res.status(401).json({ message: 'Acceso no autorizado' });
  }
});

// Iniciar el servidor
const PORT = process.env.PORT || 3007;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://database:${PORT}`);
});
