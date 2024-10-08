const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const debug = require('debug')('app:tasks');
const mysql = require('mysql');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const aws = require('aws-sdk');
const config = require('./config.json');
const { S3Client, PutObjectCommand, ListObjectsCommand } = require('@aws-sdk/client-s3');
const storageB = multer.memoryStorage();
var compression = require('compression');
const mysqlnew = require('mysql2/promise'); // Importa mysql2 con soporte para Promesas



const http = require('http');
require('dotenv').config();
const {v4: uuidv4} = require('uuid');

const uploadB = multer({ storage: storageB });

// Configurar AWS
aws.config.update(config);




const client = new S3Client({
  region: "us-east-2",
  credentials: {
    accessKeyId: "AKIAV44IJUPD6LZACKGQ",
    secretAccessKey: "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"
  }
});

async function uploadFile(file) {
  /*const stream = fs.createReadStream(file);
  const uploadParams = {
    Bucket: "mybuckerpersonal",
    Key: "hola.png",
    Body: stream
  };
  const command = new PutObjectCommand(uploadParams);
  const result = await client.send(command);
  console.log(result);*/

  try {
    const uploadParams = {
      Bucket: 'mybuckerpersonal', // Cambia por el nombre de tu bucket en S3
      Key: file.originalname,
      Body: file.buffer
    };

    const command = new PutObjectCommand(uploadParams);
    const result = await client.send(command);
    console.log('File uploaded successfully:', result);
    return result;
  } catch (error) {
    console.error('Error uploading file:', error);
    throw error;
  }
}

async function listFilesInS3(bucketName) {
  try {
    const listParams = {
      Bucket: bucketName // Nombre del bucket en S3
    };

    const command = new ListObjectsCommand(listParams);
    const response = await client.send(command);
    
    const files = response.Contents.map(file => {
      return {
        Key: file.Key,
        URL: `https://${bucketName}.s3.amazonaws.com/${file.Key}`
      };
    });
    console.log('Files in bucket:', files);
    return files;
  } catch (error) {
    console.error('Error listing files:', error);
    throw error;
  }
}


const bodyParser = require('body-parser');
const saltRounds = 10; 
const storageA = multer.memoryStorage();
const uploadA = multer({ storageA });

const app = express();
app.use(express.json());
app.use(compression());
app.use(cors());
//app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.urlencoded({ extended: true }));



const serverHttp = http.createServer(app);
serverHttp.listen(process.env.HTTP_PORT, process.env.IP);
serverHttp.on('listening', () => console.info(`Notes App running at http://${process.env.IP}:${process.env.HTTP_PORT}`));


// Contenido estático
app.use(express.static('./public'));

// Simulación de una base de datos de usuarios
const users = [];


const db = mysql.createConnection({
    host: '45.191.0.164',
    user: 'teknodat11_helpdesk', // Usuario de MySQL
    password: 'klp%PW5}k!^$', // Contraseña de MySQL
    database: 'teknodat11_helpdesk' // Nombre de tu base de datos
  });

  const pool = mysqlnew.createPool({
    host: '45.191.0.164',
    user: 'teknodat11_helpdesk', // Usuario de MySQL
    password: 'klp%PW5}k!^$', // Contraseña de MySQL
    database: 'teknodat11_helpdesk' // Nombre de tu base de datos
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

// Configuración de almacenamiento para multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

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
  db.query('SELECT * FROM help_user WHERE email = ?', [email], async (error, results) => {
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

app.post('/api/reorder', (req, res) => {
  const { startIndex, idStartIndex, endIndex, idEndIndex } = req.body;

  const updateQuery1 = `
    UPDATE tasks
    SET ordertask = ${startIndex}          
    WHERE uuid = '${idStartIndex}';
`;

const updateQuery2 = `
    UPDATE tasks
    SET ordertask = ${endIndex}          
    WHERE uuid = '${idEndIndex}';
`;

// Valores para la primera actualización
const values1 = [startIndex, idStartIndex];

// Valores para la segunda actualización
const values2 = [endIndex, idEndIndex];


// Ejecutar la primera consulta
db.query(updateQuery1, values1, (err, result) => {
    if (err) {
        return res.status(500).json({ success: false, message: 'Error actualizando el orden', error: err });
    }

    // Si la primera consulta fue exitosa, ejecutar la segunda
    db.query(updateQuery2, values2, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error actualizando el orden', error: err });
        }
        res.json({ success: true, message: 'Orden actualizado correctamente' });
    });
});

  
});

app.post('/api/register', async (req, res) => {
  const { email, password, displayName } = req.body;

  // Verificar si el usuario ya está registrado
  db.query('SELECT * FROM help_user WHERE email = ?', [email], async (error, results) => {
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
        db.query('INSERT INTO help_user (lastname, email, passwd) VALUES (?, ?, ?)', [displayName,email, hash], (error, results) => {
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



app.post('/api/uploadaws', uploadB.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const result = await uploadFile(file);
    res.json({ message: 'File uploaded successfully', data: result });
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

// Endpoint para insertar datos
app.post('/api/tasks', uploadB.single('file'), async (req, res) => {

  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const result = await uploadFile(file);
    idfileaws = result.$metadata.extendedRequestId;


    const { type, title, notes, completed, dueDate, priority, tags, assignedTo, subTasks, order } = req.body;

  const newId = uuidv4(); // Generar un nuevo UUID
  // Prepara la consulta SQL para insertar la tarea principal
  const taskQuery = `INSERT INTO tasks (type, title, notes, completed, dueDate, priority,  assignedTo, ordertask,uuid,fileaws) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?)`;

  // Ejecuta la consulta para la tarea principal
  db.query(taskQuery, [type, title, notes, completed, dueDate, priority,  assignedTo, order,newId,idfileaws], (err, result) => {
    if (err) {
      console.error('Error insertando la tarea principal:', err);
      return res.status(500).send('Error insertando la tarea principal.');
    }

    // Si hay subtareas, inserta cada una de ellas en la base de datos
    const newTaskId = newId;
 
    console.log('Datos de la tarea:', { type, title, notes, completed, dueDate, priority, tags, assignedTo, subTasks, order });
    if (tags && tags.length > 0) {
      const sqlInsertTaskTags = `INSERT INTO task_tags (taskId, tagId) VALUES ?`;
      const taskTagValues = tags.map(tagId => [newTaskId, tagId]);

      db.query(sqlInsertTaskTags, [taskTagValues], (error) => {
        if (error) {
          console.error('Error al insertar los tags:', error);
          debug('Error al insertar los tags:', error);

          return res.status(500).send('Error al insertar los tags.');
        }
        

    if (subTasks && subTasks.length > 0) {
      const subTaskQuery = `INSERT INTO sub_tasks (title, completed, taskId) VALUES ?`;
      const subTaskData = subTasks.map(subTask => [subTask.title, subTask.completed, newTaskId]);

      db.query(subTaskQuery, [subTaskData], (err, result) => {
        if (err) {
          console.error('Error insertando subtareas:', err);
          return res.status(500).send('Error insertando subtareas.');
        }

        res.status(201).send('Tarea y subtareas insertadas exitosamente.');
        
      });
    } else {
      res.status(201).send({id:newId});
    }
  });
    } else {
      res.status(201).send({id:newId});
    }
  });
    
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({ error: 'Failed to upload file' });
  }

  
});


app.put('/api/tasks/:id?', async (req, res) => {
  const taskId = req.query.id;
  const { type, title, notes, completed, dueDate, priority, tags, assignedTo, subTasks, order } = req.body;

  try {
    console.log(taskId);
    console.log(completed);
    const completedValue = completed === 'true' || completed === true ? 1 : 0;

console.log(completedValue);
    // Actualiza la tarea principal
    const updateTaskQuery = `
      UPDATE tasks 
      SET type = ?, title = ?, notes = ?, completed = ?, dueDate = ?, priority = ?, assignedTo = ?, ordertask = ?
      WHERE uuid = ?
    `;

    await pool.query(updateTaskQuery, [type, title, notes, completedValue, dueDate, priority, assignedTo, order, taskId]);

    // Elimina los tags actuales
    const deleteTaskTagsQuery = `DELETE FROM task_tags WHERE taskId = ?`;
    await pool.query(deleteTaskTagsQuery, [taskId]);

    // Inserta los nuevos tags, si existen
    if (tags && tags.length > 0) {
      const sqlInsertTaskTags = `INSERT INTO task_tags (taskId, tagId) VALUES ?`;
      const taskTagValues = tags.map(tagId => [taskId, tagId]);

      await pool.query(sqlInsertTaskTags, [taskTagValues]);
    }

    // Elimina las subtareas actuales
    const deleteSubTasksQuery = `DELETE FROM sub_tasks WHERE taskId = ?`;
    await pool.query(deleteSubTasksQuery, [taskId]);

    // Inserta las nuevas subtareas, si existen
    if (subTasks && subTasks.length > 0) {
      const subTaskQuery = `INSERT INTO sub_tasks (title, completed, taskId) VALUES ?`;
      const subTaskData = subTasks.map(subTask => [subTask.title, subTask.completed, taskId]);

      await pool.query(subTaskQuery, [subTaskData]);
    }

    // Enviar la respuesta
    res.status(200).send('Tarea y subtareas actualizadas exitosamente.');
  } catch (err) {
    console.error('Error actualizando la tarea principal:', err);
    res.status(500).send('Error actualizando la tarea.');
  }
});

app.delete('/api/tasks/:id?', async (req, res) => {
  const taskId = req.params.id;

  try {
    // Primero, eliminamos las subtareas relacionadas con la tarea
    const deleteSubTasksQuery = `DELETE FROM sub_tasks WHERE taskId = ?`;
    await pool.query(deleteSubTasksQuery, [taskId]);

    // Luego, eliminamos los tags asociados a la tarea
    const deleteTaskTagsQuery = `DELETE FROM task_tags WHERE taskId = ?`;
    await pool.query(deleteTaskTagsQuery, [taskId]);

    // Finalmente, eliminamos la tarea principal
    const deleteTaskQuery = `DELETE FROM tasks WHERE uuid = ?`;
    await pool.query(deleteTaskQuery, [taskId]);

    // Respuesta exitosa
    res.status(200).send('Tarea y sus asociaciones eliminadas exitosamente.');
  } catch (err) {
    console.error('Error eliminando la tarea:', err);
    res.status(500).send('Error eliminando la tarea.');
  }
});



app.get('/api/tasks/:id?', async (req, res) => {
  const taskId = req.query.id; // save Obtener el ID de la tarea desde los parámetros de la ruta, si existe

  // Definir la consulta SQL base
  let query = `
    SELECT 
      t.uuid as taskUuid, 
      t.type,
      t.fileaws,
      t.title,
      t.notes,
      t.completed,
      t.dueDate,
      t.priority,
      t.assignedTo,
      t.ordertask,      
      tg.id AS tagId,
      tg.id AS tagUuid,
      tg.titlesoport AS tagTitle
    FROM tasks t
    LEFT JOIN task_tags tt ON t.uuid = tt.taskId
    LEFT JOIN report_type tg ON tt.tagId = tg.id
  `;

  // Agregar condición WHERE solo si se proporciona un ID de tarea
  if (taskId) {
    query += ` WHERE t.uuid = ?`;
  }
  // Agregar el ORDER BY al final de la consulta
  query += ` ORDER BY t.ordertask ASC`;

  db.query(query, taskId ? [taskId] : [], (err, results) => {
    if (err) {
      console.error('Error al obtener las tareas:', err);
      res.status(500).send('Error al obtener las tareas');
      return;
    }

    // Organizar los resultados en un formato de JSON más estructurado
    const tasks = results.reduce((acc, row) => {
      // Buscar o crear la tarea en la lista acumulada
      let task = acc.find(t => t.id === row.taskUuid);
      if (!task) {
        task = {
          id: row.taskUuid,
          type: row.type,
          title: row.title,
          notes: row.notes,
          completed: row.completed,
          dueDate: row.dueDate,
          priority: row.priority,
          assignedTo: row.assignedTo,
          order: row.ordertask,
          files: row.fileaws,
          subTasks: [],
          tags : []
        };
        acc.push(task);
      }

      // Agregar la subtarea si existe
     /* if (row.subTaskId) {
        task.subTasks.push({
          id: row.subTaskId,
          title: row.subTaskTitle,
          completed: row.subTaskCompleted
        });
      }*/

      // Agregar el tag si existe y no se ha agregado previamente
      if (row.tagUuid && !task.tags.includes(row.tagUuid)) {
        task.tags.push(row.tagUuid); // Solo agregar el ID del tag
      }

      return acc;
    }, []);

    // Enviar los resultados como respuesta
    if (taskId) {
      res.json(tasks.length > 0 ? tasks[0] : {});
    } else {
      // Si no hay taskId, devolver todas las tareas en un array.
      res.json(tasks);
    }
  });
});



app.get('/api/task/tag', async (req, res) => {

  const token = req.headers.authorization.split(' ')[1];
  let ids = [];

  try {
    jwt.verify(token, secretKey);
    const decoded = jwt.decode(token);

    db.query('SELECT * FROM report_type ',  async (error, results) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ message: 'Error interno del servidor' });
      }
  
      if (results.length > 0) {
        results.forEach((row) => {
          ids.push( {"id":row["id"],"title":row["titlesoport"] });
        });
      }

      res.status(200).json(ids);

  });

  } catch (error) {
    res.status(401).json({ message: 'Acceso no autorizado' });
  }


  

})

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

app.post('/api/upload', upload.single('photo'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }
  res.send(`File uploaded successfully: ${req.file.filename}`);
});

// Crear directorio de uploads si no existe
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

app.get('/api/files', (req, res) => {
  fs.readdir(uploadsDir, (err, files) => {
    if (err) {
      return res.status(500).send('Error al leer la carpeta de uploads.');
    }

    res.json(files);
  });
});


app.post('/api/uploadaws', uploadB.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const result = await uploadFile(file);
    res.json({ message: 'File uploaded successfully', data: result });
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

app.get('/api/listaws', async (req, res) => {
  try {
    const files = await listFilesInS3('mybuckerpersonal');
    res.json({ files });
  } catch (error) {
    console.error('Error listing files:', error);
    res.status(500).json({ error: 'Failed to list files' });
  }
});


// Iniciar el servidor
const PORT = process.env.PORT || 3007;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://database:${PORT}`);
});
