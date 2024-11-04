const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config(); // Agrega esta línea al inicio de tu archivo
const saltRounds = 10; // Número de rondas de sal para hashing
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const estudiantesRouter = require('./routes/usuarios');
const router = express.Router();  
const Pagination = require('pagination');

const methodOverride = require('method-override');

const app = express();
const port = process.env.PORT || 3000;

// Configurar CORS
app.use(cors());

// Conexión a la base de datos MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'datos_alumnos',
  port: 3307
});

// Exportar la conexión de la base de datos para usarla en otros archivos
module.exports = db;

app.use(session({
  secret: 'tu_secreto_fuerte', // Cambia esto por una cadena secreta fuerte
  resave: false, // No resave la sesión si no ha sido modificada
  saveUninitialized: false, // No guarda sesiones no inicializadas
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // Establece la duración de la cookie (1 día en este caso)
    secure: false, // Cambia a true si usas HTTPS
    httpOnly: true // Previene el acceso a la cookie desde JavaScript del lado del cliente
  }
}));

const profileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public', 'uploads', 'perfiles'));
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Guardar con un nombre único
  }
});

const uploadProfile = multer({ storage: profileStorage });

app.post('/uploadProfile', uploadProfile.single('image'), (req, res) => {
  const userId = req.session.user.id_usuario; // Obtener el ID del usuario de la sesión
  const nombre = req.body.name;
  const imagePath = `/uploads/perfiles/${req.file.filename}`; // Ruta de la imagen subida

  const query = 'UPDATE usuarios SET nombre_usuario = ?, foto = ? WHERE id_usuario = ?';
  db.query(query, [nombre, imagePath, userId], (err, result) => {
    if (err) {
      console.error('Error al actualizar la foto de perfil:', err);
      return res.status(500).send({ success: false, message: 'Error en el servidor' });
    }

    // Actualizar la sesión con la nueva foto
    req.session.user.profilePicture = imagePath;

    res.send({ success: true, message: 'Foto de perfil actualizada exitosamente', imagePath });
  });
});

// Configuración de Multer para almacenamiento de archivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, path.join(__dirname, 'public', 'uploads'));
  },
  filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// Configuración de Multer
const storageGuide = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, path.join(__dirname, 'public', 'uploads', 'guides')); // Nueva carpeta para guías
  },
  filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname));
  }
});

const uploadGuide = multer({ storage: storageGuide });

// Middleware para manejar las peticiones POST
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.post('/upload', upload.single('image'), (req, res) => {
  if (req.file) {
      res.redirect('/album'); // Redirige a /album después de subir el archivo
  } else {
      res.status(400).send('No se ha subido ningún archivo');
  }
});

// Ruta principal
app.get('/', (req, res) => {
  res.send('Página principal');
});


app.get('/album', (req, res) => {
  fs.readdir(path.join(__dirname, 'public', 'uploads'), (err, files) => {
      if (err) {
          console.error('Error al leer el directorio de imágenes:', err);
          res.status(500).send('Error al obtener las imágenes');
          return;
      }
      // Filtrar solo archivos de imagen
      const images = files.filter(file => ['.jpg', '.jpeg', '.png'].includes(path.extname(file).toLowerCase()));
      res.render('album', { images });
  });
});

app.use((err, req, res, next) => {
  if (err) {
    return res.status(500).send('Error al subir el archivo: ' + err.message);
  }
  next();
});

app.use(methodOverride('_method'));
db.connect((err) => {
  if (err) throw err;
  console.log('Conectado a la base de datos MySQL');
});

app.use(bodyParser.urlencoded({ extended: true }));

function formatDate(dateStr) {
  const date = new Date(dateStr);
  const options = { year: 'numeric', month: 'long', day: 'numeric' };
  return date.toLocaleDateString('es-ES', options);
}

// Configuración de body-parser para manejar datos POST
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


// Configuración de las rutas estáticas y vistas
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Configuración del transportador de Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
      user: process.env.EMAIL_USER, // Usar variable de entorno
      pass: process.env.EMAIL_PASS, // Usar variable de entorno
  },
});

// Servir la vista principal
app.get('/usuarios', (req, res) => {
  res.render('usuarios/index');
});

app.post('/login', (req, res) => {
  const { email, contraseña } = req.body;

  // Verificación de campos vacíos
  if (!email || !contraseña) {
      req.session.error = 'Todos los campos son requeridos';
      return res.redirect('/login');
  }

  const query = 'SELECT id_usuario, nombre_usuario, contraseña, id_rol, foto FROM usuarios WHERE email = ? AND estado = \'activo\'';
  db.query(query, [email], (err, results) => {
      if (err) {
          console.error('Error en la consulta de usuario:', err);
          req.session.error = 'Error en el servidor';
          return res.redirect('/login');
      }

      if (results.length === 0) {
          req.session.error = 'Email, contraseña incorrectos o usuario inactivo';
          return res.redirect('/login');
      }

      const usuario = results[0];

      // Comparación de contraseña
      bcrypt.compare(contraseña, usuario.contraseña, (err, result) => {
          if (err) {
              console.error('Error al comparar la contraseña:', err);
              req.session.error = 'Error en el servidor';
              return res.redirect('/login');
          }

          if (!result) {
              req.session.error = 'Email o contraseña incorrectos';
              return res.redirect('/login');
          }

          // Obtener nombre del rol
          const getRoleNameQuery = 'SELECT nombre_rol FROM roles WHERE id_rol = ?';
          db.query(getRoleNameQuery, [usuario.id_rol], (err, roleResult) => {
              if (err) {
                  console.error('Error al obtener el nombre del rol:', err);
                  req.session.error = 'Error en el servidor';
                  return res.redirect('/login');
              }

              req.session.user = {
                  id_usuario: usuario.id_usuario,
                  nombre_usuario: usuario.nombre_usuario,
                  rol: roleResult[0].nombre_rol,
                  profilePicture: usuario.foto || '/path/to/default/profile.jpg' // Cambia esta ruta
              };

              req.session.success = 'Bienvenido, has iniciado sesión exitosamente';
              res.redirect('/dashboard'); // Ruta para el dashboard de administrador
          });
      });
  });
});

// Vista de login
app.get('/login', (req, res) => {
  const error = req.session.error;
  delete req.session.error;
  res.render('login', { error });
});

// Ruta para mostrar el dashboard de administrador
app.get('/dashboard', (req, res) => {
  if (!req.session.user || req.session.user.rol !== 'administrador') {
      return res.redirect('/login'); // Redirige si no es un administrador
  }
  
  const success = req.session.success;
  delete req.session.success;
  res.render('dashboard', { success, user: req.session.user });
});

// Ruta para iniciar sesión como profesor
app.post('/login-profesor', (req, res) => {
  const { email, contraseña } = req.body;

  // Verificación de campos vacíos
  if (!email || !contraseña) {
      req.session.error = 'Todos los campos son requeridos';
      return res.redirect('/login-profesor');
  }

  const query = 'SELECT id_usuario, nombre_usuario, contraseña, id_rol, foto FROM usuarios WHERE email = ? AND estado = "activo"';
  db.query(query, [email], (err, results) => {
      if (err) {
          console.error('Error en la consulta de usuario:', err);
          req.session.error = 'Error en el servidor';
          return res.redirect('/login-profesor');
      }

      if (results.length === 0) {
          req.session.error = 'Email o contraseña incorrectos, o usuario inactivo';
          return res.redirect('/login-profesor');
      }

      const usuario = results[0];

      // Comparación de contraseña
      bcrypt.compare(contraseña, usuario.contraseña, (err, result) => {
          if (err) {
              console.error('Error al comparar la contraseña:', err);
              req.session.error = 'Error en el servidor';
              return res.redirect('/login-profesor');
          }

          if (!result) {
              req.session.error = 'Email o contraseña incorrectos';
              return res.redirect('/login-profesor');
          }

          // Obtener el nombre del rol
          const getRoleNameQuery = 'SELECT nombre_rol FROM roles WHERE id_rol = ?';
          db.query(getRoleNameQuery, [usuario.id_rol], (err, roleResult) => {
              if (err) {
                  console.error('Error al obtener el nombre del rol:', err);
                  req.session.error = 'Error en el servidor';
                  return res.redirect('/login-profesor');
              }

              // Guardar información del usuario en la sesión
              req.session.user = {
                  id_usuario: usuario.id_usuario,
                  nombre_usuario: usuario.nombre_usuario,
                  rol: roleResult[0].nombre_rol,
                  profilePicture: usuario.foto || '/path/to/default/profile.jpg' // Cambia esta ruta si tienes una imagen predeterminada
              };

              req.session.success = 'Bienvenido, has iniciado sesión exitosamente';
              res.redirect('/dashboard-profesor'); // Redirige al dashboard de profesor
          });
      });
  });
});

// Vista de login para profesor
app.get('/login-profesor', (req, res) => {
  const error = req.session.error;
  delete req.session.error; // Elimina el error de la sesión después de mostrarlo
  res.render('profesores/login-profesor', { error });
});

// Ruta para mostrar el dashboard de profesor
app.get('/dashboard-profesor', verificarAutenticacion, (req, res) => {
  const success = req.session.success;
  delete req.session.success; // Elimina el mensaje de éxito después de mostrarlo
  res.render('dashboard-profesor', { user: req.session.user, success });
});

//contacto
app.post('/send-email', (req, res) => {
  const { nombre, email, telefono, mensaje } = req.body;

  const mailOptions = {
      from: email,
      to: 'garciafrida5tobacoc@gmail.com', // Cambia esto a la dirección de correo que desees
      subject: `Mensaje de ${nombre}`,
      text: `Nombre: ${nombre}\nTeléfono: ${telefono}\nMensaje: ${mensaje}`,
      html: `<strong>Nombre:</strong> ${nombre}<br><strong>Teléfono:</strong> ${telefono}<br><strong>Mensaje:</strong> ${mensaje}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
          console.error(error);
          return res.status(500).send('Error al enviar el correo');
      }
      console.log('Correo enviado:', info.response);
      res.send('Correo enviado con éxito');
  });
});


// módulo usuarios
// Ruta para obtener usuarios con paginación
// Ruta para obtener usuarios con paginación o todos los usuarios
app.get('/api/usuarios', (req, res) => {
  const allUsers = req.query.all === 'true'; // Comprobar si se solicita obtener todos los usuarios
  const limit = 10;
  const page = parseInt(req.query.page) || 1;
  const offset = (page - 1) * limit;

  let query;
  let queryParams = [];

  if (allUsers) {
      // Si se solicitan todos los usuarios, no aplicamos paginación
      query = `
        SELECT u.*, r.nombre_rol 
        FROM usuarios u
        JOIN roles r ON u.id_rol = r.id_rol
      `;
  } else {
      // Si no, aplicamos la paginación
      query = `
        SELECT u.*, r.nombre_rol 
        FROM usuarios u
        JOIN roles r ON u.id_rol = r.id_rol
        LIMIT ? OFFSET ?
      `;
      queryParams = [limit, offset];
  }

  db.query(query, queryParams, (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      if (!allUsers) {
          // Contar el total de usuarios para paginación solo si no se solicitan todos
          db.query('SELECT COUNT(*) AS count FROM usuarios', (err, countResult) => {
              if (err) return res.status(500).json({ error: err.message });

              res.json({
                  users: results,
                  totalPages: Math.ceil(countResult[0].count / limit)
              });
          });
      } else {
          // Si se solicitan todos los usuarios, solo devuelve los resultados
          res.json({
              users: results,
              totalPages: 1 // Puedes devolver 1 si no se usa paginación
          });
      }
  });
});



// Ruta para obtener un usuario específico
app.get('/api/usuarios/:id', (req, res) => {
  const userId = req.params.id;
  const query = 'SELECT * FROM usuarios WHERE id_usuario = ?';
  db.query(query, [userId], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

      res.json(results[0]);
  });
});

// Ruta para crear usuario y profesor
app.post('/api/usuarios', (req, res) => {
  const { nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol, especialidad, experiencia_years } = req.body;
  const hashedPassword = bcrypt.hashSync(contraseña, 10); // Hash de la contraseña
  
  const sqlUsuario = `INSERT INTO usuarios (nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
  db.query(sqlUsuario, [nombre_usuario, email, hashedPassword, telefono, direccion, fecha_nacimiento, genero, estado, id_rol], (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      const userId = result.insertId; // Obtener el ID del nuevo usuario

      // Insertar en la tabla profesores
      const sqlProfesor = `INSERT INTO profesores (id_profesor, nombre, email, especialidad, experiencia_years, fecha_ingreso) VALUES (?, ?, ?, ?, ?, ?)`;
      db.query(sqlProfesor, [userId, nombre_usuario, email, especialidad, experiencia_years, new Date()], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.status(201).json({ message: 'Usuario y profesor creados exitosamente' });
      });
  });
});

// Ruta para actualizar usuario y profesor
app.put('/api/usuarios/:id', (req, res) => {
  const id = req.params.id;
  const { nombre_usuario, email, contraseña, telefono, direccion, fecha_nacimiento, genero, estado, id_rol, especialidad, experiencia_years } = req.body;
  const hashedPassword = contraseña ? bcrypt.hashSync(contraseña, 10) : null;

  // Actualizar en la tabla usuarios
  let sqlUsuario = `UPDATE usuarios SET nombre_usuario = ?, email = ?, telefono = ?, direccion = ?, fecha_nacimiento = ?, genero = ?, estado = ?, id_rol = ?`;
  const updatesUsuario = [nombre_usuario, email, telefono, direccion, fecha_nacimiento, genero, estado, id_rol];

  if (hashedPassword) {
      sqlUsuario += ', contraseña = ?';
      updatesUsuario.push(hashedPassword);
  }
  
  sqlUsuario += ' WHERE id_usuario = ?';
  updatesUsuario.push(id);

  db.query(sqlUsuario, updatesUsuario, (err) => {
      if (err) return res.status(500).json({ error: err.message });

      // Actualizar en la tabla profesores
      const sqlProfesor = `UPDATE profesores SET nombre = ?, email = ?, especialidad = ?, experiencia_years = ? WHERE id_profesor = ?`;
      db.query(sqlProfesor, [nombre_usuario, email, especialidad, experiencia_years, id], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: 'Usuario y profesor actualizados exitosamente' });
      });
  });
});

// Ruta para eliminar usuario
app.delete('/api/usuarios/:id', async (req, res) => {
  const id = req.params.id;

  try {
      // Primero, elimina las asistencias relacionadas
      await db.query('DELETE FROM asistencias WHERE id_profesor = ?', [id]);
      
      // Luego, elimina de la tabla profesores
      await db.query('DELETE FROM profesores WHERE id_profesor = ?', [id]);
      
      // Finalmente, elimina de la tabla usuarios
      await db.query('DELETE FROM usuarios WHERE id_usuario = ?', [id]);

      res.json({ message: 'Usuario, profesor y asistencias eliminados exitosamente' });
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});


// Configuración de la carpeta de uploads
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
//modulo grados
// Ruta para mostrar la vista de grados
app.get('/grados', async (req, res) => {
  try {
      const grados = await db.query('SELECT * FROM grados');
      res.render('grados/index', { grados });
  } catch (error) {
      console.error('Error al obtener grados:', error);
      res.status(500).send('Error interno del servidor');
  }
});

app.get('/api/grados', (req, res) => {
  db.query('SELECT * FROM grados', (err, grados) => {
      if (err) {
          console.error('Error al obtener grados:', err);
          return res.status(500).json({ success: false });
      }

      const gradoPromises = grados.map(grado =>
          new Promise((resolve, reject) => {
              db.query('SELECT nombre_seccion FROM secciones WHERE id_grado = ?', [grado.id_grado], (err, secciones) => {
                  if (err) {
                      reject(err);
                  } else {
                      grado.secciones = secciones.map(seccion => seccion.nombre_seccion).join(', ');
                      resolve(grado);
                  }
              });
          })
      );

      Promise.all(gradoPromises)
          .then(result => res.json(result))
          .catch(err => {
              console.error('Error al obtener secciones:', err);
              res.status(500).json({ success: false });
          });
  });
});

// Ruta para obtener un grado específico por ID
app.get('/api/grados/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM grados WHERE id_grado = ?', [id], (err, grados) => {
      if (err) {
          console.error('Error al obtener grado:', err);
          return res.status(500).json({ success: false });
      }

      if (grados.length === 0) {
          return res.status(404).json({ success: false, message: 'Grado no encontrado' });
      }

      const grado = grados[0];

      db.query('SELECT nombre_seccion FROM secciones WHERE id_grado = ?', [id], (err, secciones) => {
          if (err) {
              console.error('Error al obtener secciones:', err);
              return res.status(500).json({ success: false });
          }

          grado.secciones = secciones.map(seccion => seccion.nombre_seccion).join(', ');
          res.json(grado);
      });
  });
});

// Crear grado
app.post('/api/grados/create', (req, res) => {
  const { nombre_grado, nivel_academico, secciones } = req.body;

  db.query('INSERT INTO grados (nombre_grado, nivel_academico) VALUES (?, ?)', 
      [nombre_grado, nivel_academico], 
      (err, result) => {
          if (err) {
              console.error('Error al insertar el grado:', err);
              return res.status(500).json({ success: false });
          }

          const id_grado = result.insertId;

          let seccionesArray = [];
          if (Array.isArray(secciones)) {
              seccionesArray = secciones;
          } else if (typeof secciones === 'string') {
              seccionesArray = secciones.split(',').map(s => s.trim());
          }

          if (seccionesArray.length > 0) {
              const sectionQueries = seccionesArray.map(seccion => 
                  new Promise((resolve, reject) => {
                      db.query('INSERT INTO secciones (id_grado, nombre_seccion) VALUES (?, ?)', 
                          [id_grado, seccion], 
                          (err) => {
                              if (err) {
                                  reject(err);
                              } else {
                                  resolve();
                              }
                          }
                      );
                  })
              );

              Promise.all(sectionQueries)
                  .then(() => res.json({ success: true }))
                  .catch(err => {
                      console.error('Error al insertar secciones:', err);
                      res.status(500).json({ success: false });
                  });
          } else {
              res.json({ success: true });
          }
      }
  );
});

// Actualizar grado
app.post('/api/grados/update', (req, res) => {
  const { id_grado, nombre_grado, nivel_academico, secciones } = req.body;

  db.query('UPDATE grados SET nombre_grado = ?, nivel_academico = ? WHERE id_grado = ?', 
      [nombre_grado, nivel_academico, id_grado], 
      (err) => {
          if (err) {
              console.error('Error al actualizar el grado:', err);
              return res.status(500).json({ success: false });
          }

          db.query('DELETE FROM secciones WHERE id_grado = ?', [id_grado], (err) => {
              if (err) {
                  console.error('Error al eliminar secciones:', err);
                  return res.status(500).json({ success: false });
              }

              let seccionesArray = [];
              if (typeof secciones === 'string') {
                  seccionesArray = secciones.split(',').map(s => s.trim());
              } else if (Array.isArray(secciones)) {
                  seccionesArray = secciones;
              }

              if (seccionesArray.length > 0) {
                  const sectionQueries = seccionesArray.map(seccion => 
                      new Promise((resolve, reject) => {
                          db.query('INSERT INTO secciones (id_grado, nombre_seccion) VALUES (?, ?)', 
                              [id_grado, seccion], 
                              (err) => {
                                  if (err) {
                                      reject(err);
                                  } else {
                                      resolve();
                                  }
                              }
                          );
                      })
                  );

                  Promise.all(sectionQueries)
                      .then(() => res.json({ success: true }))
                      .catch(err => {
                          console.error('Error al insertar secciones:', err);
                          res.status(500).json({ success: false });
                      });
              } else {
                  res.json({ success: true });
              }
          });
      }
  );
});

// Eliminar grado
app.post('/api/grados/delete', (req, res) => {
  const { id_grado } = req.body;

  db.query('DELETE FROM grados WHERE id_grado = ?', [id_grado], (err) => {
      if (err) {
          console.error('Error al eliminar el grado:', err);
          return res.status(500).json({ success: false });
      }

      db.query('DELETE FROM secciones WHERE id_grado = ?', [id_grado], (err) => {
          if (err) {
              console.error('Error al eliminar secciones:', err);
              return res.status(500).json({ success: false });
          }
          res.json({ success: true });
      });
  });
});

// Módulo alumnos
app.get('/api/alumnos', (req, res) => {
  // Suponiendo que usas MySQL
  db.query('SELECT * FROM alumnos', (error, results) => {
      if (error) return res.status(500).send(error);
      res.json(results);
  });
});

// Obtener todos los alumnos
// Rutas para alumnos
app.get('/alumnos', (req, res) => {
  db.query('SELECT * FROM alumnos', (err, results) => {
      if (err) return res.status(500).send(err);
      res.render('alumnos', { alumnos: results });
  });
});

// Ruta para obtener un alumno por ID (incluye información de padres si es necesario)
app.get('/alumnos/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM alumnos WHERE id_alumno = ?', [id], (err, results) => {
      if (err) return res.status(500).send(err);
      if (results.length === 0) return res.status(404).send('Alumno no encontrado');
      res.json(results[0]); // Devuelve el alumno encontrado
  });
});

// Obtener todos los grados
app.get('/grados', (req, res) => {
  db.query('SELECT * FROM grados', (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results);
  });
});
// Agregar un nuevo alumno
app.post('/alumnos', (req, res) => {
  const { nombre, apellido, fecha_nacimiento, email, telefono, seccion, estado, id_grado, 
          nombre_padre, telefono_padre, correo_padre, 
          nombre_madre, telefono_madre, correo_madre } = req.body;
  
  // Consulta SQL para insertar el nuevo alumno con los datos de los padres
  const query = `
    INSERT INTO alumnos (nombre, apellido, fecha_nacimiento, email, telefono, seccion, estado, id_grado, 
                         nombre_padre, telefono_padre, correo_padre, 
                         nombre_madre, telefono_madre, correo_madre)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  // Ejecutar la consulta con los valores proporcionados
  db.query(query, 
    [nombre, apellido, fecha_nacimiento, email, telefono, seccion, estado, id_grado, 
     nombre_padre, telefono_padre, correo_padre, 
     nombre_madre, telefono_madre, correo_madre], 
    (err, results) => {
      if (err) return res.status(500).send(err);

      // Obtener el ID del nuevo alumno
      const nuevoAlumnoId = results.insertId;

      // Consultar el nuevo alumno para devolverlo como respuesta
      db.query('SELECT * FROM alumnos WHERE id_alumno = ?', [nuevoAlumnoId], (err, results) => {
          if (err) return res.status(500).send(err);
          res.json(results[0]); // Enviar el nuevo alumno como respuesta
      });
  });
});


app.delete('/alumnos/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM alumnos WHERE id_alumno = ?', [id], (err) => {
      if (err) return res.status(500).send(err);
      res.send('Alumno eliminado');
  });
});

//actualizar alumno
app.put('/alumnos/:id', (req, res) => {
  const { id } = req.params;
  const { 
    nombre, apellido, fecha_nacimiento, email, telefono, seccion, estado, id_grado, 
    nombre_padre, telefono_padre, correo_padre, 
    nombre_madre, telefono_madre, correo_madre 
  } = req.body;

  const query = `
    UPDATE alumnos 
    SET nombre=?, apellido=?, fecha_nacimiento=?, email=?, telefono=?, seccion=?, estado=?, id_grado=?, 
        nombre_padre=?, telefono_padre=?, correo_padre=?, 
        nombre_madre=?, telefono_madre=?, correo_madre=? 
    WHERE id_alumno=?`;

  const values = [
    nombre, apellido, fecha_nacimiento, email, telefono, seccion, estado, id_grado, 
    nombre_padre, telefono_padre, correo_padre, 
    nombre_madre, telefono_madre, correo_madre, 
    id
  ];

  db.query(query, values, (err) => {
    if (err) {
      console.error(err); // Imprimir el error en consola
      return res.status(500).send('Error al actualizar el alumno');
    }

    // Si la actualización fue exitosa, realizar una consulta para devolver los datos actualizados
    db.query('SELECT * FROM alumnos WHERE id_alumno = ?', [id], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error al obtener los datos actualizados');
      }

      // Devolver los datos del alumno actualizado
      res.json(results[0]);
    });
  });
});

//modulo profesores
// Ruta para mostrar la vista de profesores
app.get('/profesores', (req, res) => {
  const sql = `
      SELECT p.id_profesor, p.nombre, p.email, p.especialidad, p.experiencia_years, 
             GROUP_CONCAT(DISTINCT g.nombre_grado ORDER BY g.nombre_grado ASC SEPARATOR ', ') AS grados,
             GROUP_CONCAT(DISTINCT s.nombre_seccion ORDER BY s.nombre_seccion ASC SEPARATOR ', ') AS secciones,
             p.fecha_ingreso
      FROM profesores p
      LEFT JOIN profesores_grados pg ON p.id_profesor = pg.id_profesor
      LEFT JOIN grados g ON pg.id_grado = g.id_grado
      LEFT JOIN secciones s ON pg.id_seccion = s.id_seccion
      GROUP BY p.id_profesor
  `;
  
  db.query(sql, (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      // Lista de grados
      const grados = [
          // ... tus grados aquí
          { id: 5, nombre: 'Primero Primaria' },
          { id: 6, nombre: 'Segundo Primaria' },
          { id: 7, nombre: 'Tercero Primaria' },
          { id: 8, nombre: 'Cuarto Primaria' },
          { id: 9, nombre: 'Quinto Primaria' },
          { id: 12, nombre: 'Sexto Primaria' },
          { id: 13, nombre: 'Primero Básico' },
          { id: 14, nombre: 'Segundo Básico' },
          { id: 15, nombre: 'Tercero Básico' },
          { id: 20, nombre: 'Bachillerato en Ciencias Biológicas' },
          { id: 21, nombre: 'Bachillerato en Computación' },
          { id: 22, nombre: 'Bachillerato en Medicina' },
          { id: 23, nombre: 'Bachillerato en Magisterio' },
          { id: 26, nombre: 'Bachillerato en Turismo' },
          { id: 27, nombre: 'Bachillerato en Criminología' },
          { id: 29, nombre: 'Bachillerato en Secretariado' },
          { id: 30, nombre: 'Perito Contador' },
      ];

      // Lista de secciones asociadas a cada grado
      const secciones = [
          // ... tus secciones aquí
          { id: 153, id_grado: 20, nombre: 'A' },
          { id: 154, id_grado: 20, nombre: 'B' },
          { id: 155, id_grado: 20, nombre: 'C' },
          { id: 158, id_grado: 21, nombre: 'A' },
          { id: 159, id_grado: 21, nombre: 'B' },
          { id: 160, id_grado: 21, nombre: 'C' },
          { id: 162, id_grado: 22, nombre: 'B' },
          { id: 163, id_grado: 22, nombre: 'C' },
          { id: 164, id_grado: 23, nombre: 'A' },
          { id: 165, id_grado: 23, nombre: 'B' },
          { id: 166, id_grado: 23, nombre: 'C' },
          { id: 180, id_grado: 6,  nombre: 'A' },
          { id: 181, id_grado: 6,  nombre: 'B' },
          { id: 182, id_grado: 6,  nombre: 'C' },
          { id: 190, id_grado: 7,  nombre: 'A' },
          { id: 191, id_grado: 7,  nombre: 'B' },
          { id: 192, id_grado: 7,  nombre: 'C' },
          { id: 193, id_grado: 8,  nombre: 'A' },
          { id: 194, id_grado: 8,  nombre: 'B' },
          { id: 195, id_grado: 8,  nombre: 'C' },
          { id: 196, id_grado: 9,  nombre: 'A' },
          { id: 197, id_grado: 9,  nombre: 'B' },
          { id: 198, id_grado: 9,  nombre: 'C' },
          { id: 199, id_grado: 12, nombre: 'A' },
          { id: 200, id_grado: 12, nombre: 'B' },
          { id: 201, id_grado: 12, nombre: 'C' },
          { id: 202, id_grado: 13, nombre: 'A' },
          { id: 203, id_grado: 13, nombre: 'B' },
          { id: 204, id_grado: 13, nombre: 'C' },
          { id: 205, id_grado: 14, nombre: 'A' },
          { id: 206, id_grado: 14, nombre: 'B' },
          { id: 207, id_grado: 14, nombre: 'C' },
          { id: 208, id_grado: 15, nombre: 'A' },
          { id: 209, id_grado: 15, nombre: 'B' },
          { id: 210, id_grado: 15, nombre: 'C' },
          { id: 211, id_grado: 26, nombre: 'A' },
          { id: 212, id_grado: 26, nombre: 'B' },
          { id: 213, id_grado: 26, nombre: 'C' },
          { id: 217, id_grado: 27, nombre: 'A' },
          { id: 218, id_grado: 27, nombre: 'B' },
          { id: 219, id_grado: 27, nombre: 'C' },
          { id: 226, id_grado: 29, nombre: 'A' },
          { id: 230, id_grado: 30, nombre: 'A' },
          { id: 231, id_grado: 30, nombre: 'B' },
          { id: 232, id_grado: 30, nombre: 'C' },
          { id: 233, id_grado: 30, nombre: 'D' },
          { id: 238, id_grado: 5,  nombre: 'A' },
          { id: 239, id_grado: 5,  nombre: 'B' },
      ];

      // Renderiza la vista y pasa los datos
      res.render('profesores/index', { profesores: results, grados, secciones });
  });
});

// Obtener un profesor por ID
app.get('/profesores/:id', (req, res) => {
  const idProfesor = req.params.id;

  const queryProfesor = `SELECT * FROM profesores WHERE id_profesor = ?`;
  const queryGrados = `SELECT id_grado, id_seccion FROM profesores_grados WHERE id_profesor = ?`;

  db.query(queryProfesor, [idProfesor], (error, resultsProfesor) => {
      if (error) return res.status(500).json({ error: 'Error al obtener el profesor' });

      db.query(queryGrados, [idProfesor], (error, resultsGrados) => {
          if (error) return res.status(500).json({ error: 'Error al obtener grados y secciones' });

          // Combina los resultados y envía
          res.json({ profesor: resultsProfesor[0], grados: resultsGrados });
      });
  });
});

//agregar profesor
// Agregar profesor
app.post('/ruta/para/agregar/profesor', (req, res) => {
  const { nombre, email, especialidad, experiencia_years, id_grado, id_seccion, fecha_ingreso } = req.body;

  if (!nombre || !email || !especialidad || !experiencia_years || !id_grado || !id_seccion || !fecha_ingreso) {
      return res.status(400).json({ error: 'Todos los campos son requeridos' });
  }

  const queryInsertProfesor = `INSERT INTO profesores (nombre, email, especialidad, experiencia_years, fecha_ingreso) VALUES (?, ?, ?, ?, ?)`;
  const valuesInsertProfesor = [nombre, email, especialidad, experiencia_years, fecha_ingreso];

  db.query(queryInsertProfesor, valuesInsertProfesor, (error, results) => {
      if (error) {
          return res.status(500).json({ error: 'Error al agregar el profesor' });
      }

      const idNuevoProfesor = results.insertId;

      // Insertar múltiples grados y secciones
      const queryInsertGrados = `INSERT INTO profesores_grados (id_grado, id_seccion, id_profesor) VALUES ?`;
      const valuesInsertGrados = id_grado.map((grado, index) => [grado, id_seccion[index], idNuevoProfesor]);

      db.query(queryInsertGrados, [valuesInsertGrados], (error) => {
          if (error) {
              return res.status(500).json({ error: 'Error al agregar en profesores_grados' });
          }
          res.status(201).json({ message: 'Profesor agregado exitosamente' });
      });
  });
});

//actualizar
app.put('/profesores/:id', (req, res) => {
  const idProfesor = req.params.id;
  const { nombre, email, especialidad, experiencia_years, grados, secciones, fecha_ingreso } = req.body;

  // Validación
  if (!nombre || !email || !especialidad || !experiencia_years || !grados || !secciones || !fecha_ingreso) {
      return res.status(400).json({ error: 'Todos los campos son requeridos' });
  }

  // Actualizar datos del profesor
  const queryUpdateProfesor = `UPDATE profesores SET nombre=?, email=?, especialidad=?, experiencia_years=?, fecha_ingreso=? WHERE id_profesor=?`;
  const valuesUpdateProfesor = [nombre, email, especialidad, experiencia_years, fecha_ingreso, idProfesor];

  db.query(queryUpdateProfesor, valuesUpdateProfesor, (error) => {
      if (error) {
          return res.status(500).json({ error: 'Error al actualizar el profesor' });
      }

      // Eliminar registros de grados y secciones existentes
      const queryDeleteGrados = `DELETE FROM profesores_grados WHERE id_profesor = ?`;
      db.query(queryDeleteGrados, [idProfesor], (error) => {
          if (error) {
              return res.status(500).json({ error: 'Error al eliminar registros previos' });
          }

          // Insertar nuevos grados y secciones
          const queryInsertGrados = `INSERT INTO profesores_grados (id_grado, id_seccion, id_profesor) VALUES ?`;
          const valuesInsertGrados = grados.map((grado, index) => [grado, secciones[index], idProfesor]);

          db.query(queryInsertGrados, [valuesInsertGrados], (error) => {
              if (error) {
                  return res.status(500).json({ error: 'Error al agregar en profesores_grados' });
              }
              res.status(200).json({ message: 'Actualización exitosa' });
          });
      });
  });
});

// Eliminar un profesor
app.delete('/profesores/:id', (req, res) => {
  const { id } = req.params;
  const query = 'DELETE FROM profesores WHERE id_profesor = ?';
  db.query(query, [id], (err) => {
      if (err) return res.status(500).send(err);
      res.send({ message: 'Profesor eliminado correctamente.' });
  });
});

//módulo de cursos

// Ruta para obtener todos los cursos

app.get('/cursos', (req, res) => {
  const sql = `
    SELECT 
        c.id_curso,
        c.nombre_curso,
        c.descripcion,
        g.nombre_grado,
        p.nombre AS nombre_profesor,
        c.estado,
        GROUP_CONCAT(a.nombre) AS alumnos -- Obtener nombres de alumnos
    FROM 
        cursos c
    JOIN 
        grados g ON c.id_grado = g.id_grado
    JOIN 
        profesores p ON c.id_profesor = p.id_profesor
    LEFT JOIN 
        inscripciones i ON c.id_curso = i.id_curso
    LEFT JOIN 
        alumnos a ON i.id_alumno = a.id_alumno -- Unir con la tabla de alumnos
    GROUP BY 
        c.id_curso;
`;

db.query(sql, (err, cursos) => {
  if (err) return res.status(500).send(err);

  const gradosSql = 'SELECT * FROM grados';
  const profesoresSql = 'SELECT * FROM profesores';
  const alumnosSql = 'SELECT * FROM alumnos'; // Consulta para obtener los alumnos

  db.query(gradosSql, (err, grados) => {
      if (err) return res.status(500).send(err);
      db.query(profesoresSql, (err, profesores) => {
          if (err) return res.status(500).send(err);
          db.query(alumnosSql, (err, alumnos) => { // Consultar alumnos
              if (err) return res.status(500).send(err);

              const message = req.session.message;  
              req.session.message = null;  

              // Pasar los cursos, grados, profesores y alumnos a la vista
              res.render('cursos/index', { cursos, grados, profesores, alumnos, message });
          });
      });
  });
});
});

// Ruta para crear un nuevo curso
app.post('/cursos/crear', (req, res) => {
  const { nombre_curso, descripcion, id_grado, id_profesor, estado, alumnos } = req.body; // Asegúrate de incluir `alumnos`
  const sql = 'INSERT INTO cursos (nombre_curso, descripcion, id_grado, id_profesor, estado) VALUES (?, ?, ?, ?, ?)';
  
  db.query(sql, [nombre_curso, descripcion, id_grado, id_profesor, estado], (err, result) => {
      if (err) {
          req.session.message = { type: 'danger', content: 'Error al crear el curso.' };
          return res.redirect('/cursos');
      }
      
      const cursoId = result.insertId; // Obtén el ID del curso recién creado

      // Ahora, guarda la relación entre el curso y los alumnos
      if (alumnos && alumnos.length > 0) {
          const inscripcionSql = 'INSERT INTO inscripciones (id_curso, id_alumno) VALUES (?, ?)';
          alumnos.forEach(alumnoId => {
              db.query(inscripcionSql, [cursoId, alumnoId], (err) => {
                  if (err) {
                      console.error(`Error al asociar alumno ${alumnoId} con el curso:`, err);
                  }
              });
          });
      }

      req.session.message = { type: 'success', content: 'Curso creado exitosamente.' };
      res.redirect('/cursos');
  });
});

// Ruta para editar un curso
app.post('/cursos/editar/:id', (req, res) => {
  const { id } = req.params;
  const { nombre_curso, descripcion, id_grado, id_profesor, estado, alumnos } = req.body;

  // Actualizar los detalles del curso
  const sqlCurso = 'UPDATE cursos SET nombre_curso = ?, descripcion = ?, id_grado = ?, id_profesor = ?, estado = ? WHERE id_curso = ?';
  db.query(sqlCurso, [nombre_curso, descripcion, id_grado, id_profesor, estado, id], (err) => {
      if (err) {
          req.session.message = { type: 'danger', content: 'Error al editar el curso.' };
          return res.redirect('/cursos');
      }

      // Eliminar las inscripciones anteriores
      const sqlEliminarInscripciones = 'DELETE FROM inscripciones WHERE id_curso = ?';
      db.query(sqlEliminarInscripciones, [id], (err) => {
          if (err) {
              req.session.message = { type: 'danger', content: 'Error al eliminar inscripciones anteriores.' };
              return res.redirect('/cursos');
          }

          // Si hay alumnos seleccionados, insertarlos en la tabla de inscripciones
          if (alumnos) {
              const inscripciones = Array.isArray(alumnos) ? alumnos : [alumnos];
              const sqlInscripcion = 'INSERT INTO inscripciones (id_alumno, id_curso) VALUES ?';
              const inscripcionesValues = inscripciones.map(id_alumno => [id_alumno, id]);

              db.query(sqlInscripcion, [inscripcionesValues], (err) => {
                  if (err) {
                      req.session.message = { type: 'danger', content: 'Error al inscribir alumnos.' };
                      return res.redirect('/cursos');
                  }
                  req.session.message = { type: 'success', content: 'Curso editado y alumnos inscritos exitosamente.' };
                  res.redirect('/cursos');
              });
          } else {
              req.session.message = { type: 'success', content: 'Curso editado sin inscribir alumnos.' };
              res.redirect('/cursos');
          }
      });
  });
});

// Ruta para eliminar un curso
app.post('/cursos/eliminar/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM cursos WHERE id_curso = ?';
  db.query(sql, [id], (err) => {
      if (err) {
          req.session.message = { type: 'danger', content: 'Error al eliminar el curso.' };
          return res.redirect('/cursos');
      }
      req.session.message = { type: 'success', content: 'Curso eliminado exitosamente.' };
      res.redirect('/cursos');
  });
});

//modulo horarios 
// Renderizar la vista de horarios
app.get('/horarios', (req, res) => {
  const idProfesor = req.query.profesor || null;
  let profesores = [];
  let horarios = [];
  let cursos = []; // Variable para cursos
  let grados = []; // Variable para grados
  let secciones = []; // Variable para secciones
  let nombreProfesor = '';
  const message = req.session.message; // Obtener mensaje de la sesión
  req.session.message = null; // Limpiar el mensaje después de obtenerlo

  // Obtener lista de profesores
  db.query('SELECT id_profesor, nombre FROM profesores', (error, profesoresRows) => {
    if (error) {
      console.error('Error al obtener la lista de profesores:', error);
      return res.status(500).send('Error al obtener la lista de profesores');
    }

    profesores = Array.isArray(profesoresRows) ? profesoresRows : [];
    console.log('Profesores:', profesores);

    // Consulta para obtener los cursos
    db.query('SELECT * FROM cursos', (error, cursosRows) => {
      if (error) {
        console.error('Error al obtener la lista de cursos:', error);
        return res.status(500).send('Error al obtener la lista de cursos');
      }

      cursos = Array.isArray(cursosRows) ? cursosRows : [];
      console.log('Cursos:', cursos);

      // Consulta para obtener los grados
      db.query('SELECT * FROM grados', (error, gradosRows) => {
        if (error) {
          console.error('Error al obtener la lista de grados:', error);
          return res.status(500).send('Error al obtener la lista de grados');
        }

        grados = Array.isArray(gradosRows) ? gradosRows : [];
        console.log('Grados:', grados);

        // Consulta para obtener solo las secciones A, B, C y D usando sus id_seccion
        db.query('SELECT * FROM secciones WHERE id_seccion IN (153, 154, 155, 233)', (error, seccionesRows) => {
          if (error) {
            console.error('Error al obtener la lista de secciones:', error);
            return res.status(500).send('Error al obtener la lista de secciones');
          }

          secciones = Array.isArray(seccionesRows) ? seccionesRows : [];
          console.log('Secciones:', secciones);

          if (idProfesor) {
            db.query(`SELECT h.*, c.nombre_curso, g.nombre_grado, s.nombre_seccion 
              FROM horarios h 
              JOIN cursos c ON h.id_curso = c.id_curso 
              JOIN grados g ON h.id_grado = g.id_grado 
              JOIN secciones s ON h.id_seccion = s.id_seccion 
              WHERE h.id_profesor = ? AND h.id_seccion IN (153, 154, 155, 233)`, [idProfesor], (error, horariosRows) => {
              if (error) {
                console.error('Error al obtener los horarios:', error);
                return res.status(500).send('Error al obtener los horarios');
              }

              horarios = Array.isArray(horariosRows) ? horariosRows : [];
              console.log('Horarios:', horarios);

              // Obtener nombre del profesor
              db.query('SELECT nombre FROM profesores WHERE id_profesor = ?', [idProfesor], (error, profesorRows) => {
                if (error) {
                  console.error('Error al obtener el nombre del profesor:', error);
                } else {
                  nombreProfesor = profesorRows.length > 0 ? profesorRows[0].nombre : '';
                }

                // Renderizar la vista con los datos obtenidos
                res.render('horarios/index', { profesores, horarios, cursos, grados, secciones, idProfesor, nombreProfesor, message });
              });
            });
          } else {
            // Renderizar la vista sin horarios
            res.render('horarios/index', { profesores, horarios, cursos, grados, secciones, idProfesor, nombreProfesor, message });
          }
        });
      });
    });
  });
});


// Agregar un nuevo horario
app.post('/horarios/agregar', async (req, res) => {
  const { dia_semana, hora_inicio, hora_fin, id_curso, id_grado, id_seccion, id_profesor } = req.body;

  try {
      await db.query('INSERT INTO horarios (dia_semana, hora_inicio, hora_fin, id_curso, id_grado, id_seccion, id_profesor) VALUES (?, ?, ?, ?, ?, ?, ?)', 
          [dia_semana, hora_inicio, hora_fin, id_curso, id_grado, id_seccion, id_profesor]
      );
      req.session.message = { type: 'success', content: 'Horario agregado exitosamente.' };
  } catch (error) {
      console.error('Error al agregar el horario:', error);
      req.session.message = { type: 'danger', content: 'Error al agregar el horario.' };
  }

  res.redirect('/horarios?profesor=' + id_profesor);
});

app.post('/horarios/editar/:id', (req, res) => {
  const idHorario = req.params.id;
  const { dia_semana, hora_inicio, hora_fin, id_curso, id_grado, id_seccion, id_profesor } = req.body;

  db.query('UPDATE horarios SET dia_semana = ?, hora_inicio = ?, hora_fin = ?, id_curso = ?, id_grado = ?, id_seccion = ?, id_profesor = ? WHERE id_horario = ?', 
      [dia_semana, hora_inicio, hora_fin, id_curso, id_grado, id_seccion, id_profesor, idHorario], (error, results) => {
      if (error) {
          console.error('Error al actualizar el horario:', error);
          req.session.message = { type: 'danger', content: 'Error al actualizar el horario.' };
          return res.redirect('/horarios?profesor=' + id_profesor);
      }

      req.session.message = { type: 'success', content: 'Horario actualizado exitosamente.' };
      res.redirect('/horarios?profesor=' + id_profesor);
  });
});

app.post('/horarios/eliminar/:id', (req, res) => {
  const { id } = req.params;

  db.query('SELECT id_profesor FROM horarios WHERE id_horario = ?', [id], (err, results) => {
      if (err) {
          console.error('Error al obtener el horario:', err);
          req.session.message = { type: 'danger', content: 'Error al obtener el horario.' };
          return res.redirect('/horarios');
      }

      if (results.length > 0) {
          const horario = results[0];

          db.query('DELETE FROM horarios WHERE id_horario = ?', [id], (err, result) => {
              if (err) {
                  console.error('Error al eliminar el horario:', err);
                  req.session.message = { type: 'danger', content: 'Error al eliminar el horario.' };
                  return res.redirect('/horarios?profesor=' + horario.id_profesor);
              }

              req.session.message = { type: 'success', content: 'Horario eliminado exitosamente.' };
              res.redirect(`/horarios?profesor=${horario.id_profesor}`);
          });
      } else {
          req.session.message = { type: 'danger', content: 'Horario no encontrado.' };
          res.redirect('/horarios');
      }
  });
});

//modulo de asistencias
// Ruta para obtener la página de asistencias
app.get('/asistencias', (req, res) => {
  console.log("Solicitando la página de asistencias...");
  // Ejecutar la consulta SQL para obtener los profesores
  db.query('SELECT * FROM profesores', (error, profesores) => {
      if (error) {
          console.error("Error al obtener los profesores:", error);
          return res.status(500).send('Error al obtener los profesores');
      }
      console.log("Profesores obtenidos:", profesores);
      // Renderizar la vista con los datos de profesores
      res.render('asistencias/index', { profesores });
  });
});

// Ruta para registrar asistencia
// Ruta para registrar asistencia
app.post('/asistencias/registrar', (req, res) => {
  const { fecha, asistencia } = req.body;

  if (!fecha || !asistencia || asistencia.length === 0) {
      req.session.message = { type: 'danger', content: 'Datos de asistencia inválidos.' };
      return res.redirect('/asistencias');
  }

  const query = 'INSERT INTO asistencias (id_profesor, estado, fecha) VALUES ?';
  const values = asistencia.map(item => [item.idProfesor, item.estado, fecha]);

  console.log("Valores para insertar:", values); // Debugging line

  db.query(query, [values], (error, results) => {
      if (error) {
          console.error('Error al registrar la asistencia:', error);
          req.session.message = { type: 'danger', content: 'Error al registrar la asistencia.' };
          return res.redirect('/asistencias');
      }

      console.log("Resultado de la inserción:", results); // Verifica que tenga filas afectadas
      req.session.message = { type: 'success', content: 'Asistencia registrada con éxito.' };
      res.redirect('/asistencias');
  });
});


//modulo de periodos escolares
// Ruta para obtener todos los períodos
app.get('/periodos', (req, res) => {
  db.query('SELECT * FROM periodos_escolares', (err, resultados) => {
      if (err) throw err;
      res.render('periodos/index', { periodos: resultados, session: req.session }); // Pasa la sesión a la vista
  });
});

// Ruta para crear un nuevo período
app.post('/periodos/crear', (req, res) => {
  const { nombre_periodo, fecha_inicio, fecha_fin, estado } = req.body;
  const sql = 'INSERT INTO periodos_escolares (nombre_periodo, fecha_inicio, fecha_fin, estado) VALUES (?, ?, ?, ?)';
  
  db.query(sql, [nombre_periodo, fecha_inicio, fecha_fin, estado], (err) => {
    if (err) {
      req.session.message = { type: 'error', content: 'Error al crear el período escolar.' };
      return res.redirect('/periodos');
    }
    req.session.message = { type: 'success', content: 'Período escolar creado exitosamente.' };
    res.redirect('/periodos');
  });
});


// Ruta para editar un período (cargar el formulario)
app.get('/periodos/editar/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM periodos_escolares WHERE id_periodo = ?', [id], (err, resultados) => {
      if (err) throw err;
      res.render('periodos/editar', { periodo: resultados[0] });
  });
});

// Ruta para actualizar un período
// Ruta para actualizar un período
app.post('/periodos/editar/:id', (req, res) => {
  const { id } = req.params;
  const { nombre_periodo, fecha_inicio, fecha_fin, estado } = req.body;
  const sql = 'UPDATE periodos_escolares SET nombre_periodo = ?, fecha_inicio = ?, fecha_fin = ?, estado = ? WHERE id_periodo = ?';

  db.query(sql, [nombre_periodo, fecha_inicio, fecha_fin, estado, id], (err) => {
    if (err) {
      req.session.message = { type: 'error', content: 'Error al actualizar el período escolar.' };
      return res.redirect('/periodos');
    }
    req.session.message = { type: 'success', content: 'Período escolar actualizado exitosamente.' };
    res.redirect('/periodos');
  });
});

// Ruta para eliminar un período
// Ruta para eliminar un período
app.post('/periodos/eliminar/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM periodos_escolares WHERE id_periodo = ?';

  db.query(sql, [id], (err) => {
    if (err) {
      req.session.message = { type: 'error', content: 'Error al eliminar el período escolar.' };
      return res.redirect('/periodos');
    }
    req.session.message = { type: 'success', content: 'Período escolar eliminado exitosamente.' };
    res.redirect('/periodos');
  });
});


// Ruta para migrar datos de un período a otro
app.post('/periodos/migrar', (req, res) => {
  const { id_periodo_origen, id_periodo_destino } = req.body;

  // Función para ejecutar una consulta y manejar errores
  const executeQuery = (query, params) => {
      return new Promise((resolve, reject) => {
          db.query(query, params, (err, result) => {
              if (err) return reject(err);
              resolve(result);
          });
      });
  };

  // Migrar alumnos
  const migrateAlumnos = () => {
      const sqlAlumnos = `
          INSERT INTO alumnos 
          (nombre, apellido, fecha_nacimiento, email, telefono, seccion, estado, id_grado, nombre_padre, telefono_padre, correo_padre, nombre_madre, telefono_madre, correo_madre, id_periodo) 
          SELECT nombre, apellido, fecha_nacimiento, email, telefono, seccion, estado, id_grado, nombre_padre, telefono_padre, correo_padre, nombre_madre, telefono_madre, correo_madre, ? 
          FROM alumnos WHERE id_periodo = ?`;
      return executeQuery(sqlAlumnos, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar asistencias
  const migrateAsistencias = () => {
      const sqlAsistencias = `
          INSERT INTO asistencias 
          (id_profesor, fecha, estado, id_periodo) 
          SELECT id_profesor, fecha, estado, ? 
          FROM asistencias WHERE id_periodo = ?`;
      return executeQuery(sqlAsistencias, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar cursos
  const migrateCursos = () => {
      const sqlCursos = `
          INSERT INTO cursos 
          (nombre_curso, descripcion, id_grado, id_profesor, estado, id_periodo) 
          SELECT nombre_curso, descripcion, id_grado, id_profesor, estado, ? 
          FROM cursos WHERE id_periodo = ?`;
      return executeQuery(sqlCursos, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar grados
  const migrateGrados = () => {
      const sqlGrados = `
          INSERT INTO grados 
          (nombre_grado, nivel_academico, id_periodo) 
          SELECT nombre_grado, nivel_academico, ? 
          FROM grados WHERE id_periodo = ?`;
      return executeQuery(sqlGrados, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar horarios
  const migrateHorarios = () => {
      const sqlHorarios = `
          INSERT INTO horarios 
          (id_curso, dia_semana, hora_inicio, hora_fin, id_profesor, id_grado, id_seccion, id_periodo) 
          SELECT id_curso, dia_semana, hora_inicio, hora_fin, id_profesor, id_grado, id_seccion, ? 
          FROM horarios WHERE id_periodo = ?`;
      return executeQuery(sqlHorarios, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar inscripciones
  const migrateInscripciones = () => {
      const sqlInscripciones = `
          INSERT INTO inscripciones 
          (id_alumno, id_curso, id_periodo) 
          SELECT id_alumno, id_curso, ? 
          FROM inscripciones WHERE id_periodo = ?`;
      return executeQuery(sqlInscripciones, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar pagos
  const migratePagos = () => {
      const sqlPagos = `
          INSERT INTO pagos 
          (fecha_pago, monto, id_estudiante, id_usuario, id_periodo) 
          SELECT fecha_pago, monto, id_estudiante, id_usuario, ? 
          FROM pagos WHERE id_periodo = ?`;
      return executeQuery(sqlPagos, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar recibos
  const migrateRecibos = () => {
      const sqlRecibos = `
          INSERT INTO recibos 
          (fecha_emision, monto, id_estudiante, id_usuario, id_periodo) 
          SELECT fecha_emision, monto, id_estudiante, id_usuario, ? 
          FROM recibos WHERE id_periodo = ?`;
      return executeQuery(sqlRecibos, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar reportes
  const migrateReportes = () => {
      const sqlReportes = `
          INSERT INTO reportes 
          (tipo_reporte, fecha_generacion, contenido, id_usuario, id_periodo) 
          SELECT tipo_reporte, fecha_generacion, contenido, id_usuario, ? 
          FROM reportes WHERE id_periodo = ?`;
      return executeQuery(sqlReportes, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar roles
  const migrateRoles = () => {
    const sqlRoles = `
        INSERT INTO roles 
        (nombre_rol, id_periodo) 
        SELECT nombre_rol, ? 
        FROM roles WHERE id_periodo = ?`;
    return executeQuery(sqlRoles, [id_periodo_destino, id_periodo_origen]); // Cambiar id_periodo para el nuevo periodo
};


  // Migrar secciones
  const migrateSecciones = () => {
      const sqlSecciones = `
          INSERT INTO secciones 
          (id_grado, nombre_seccion, id_periodo) 
          SELECT id_grado, nombre_seccion, ? 
          FROM secciones WHERE id_periodo = ?`;
      return executeQuery(sqlSecciones, [id_periodo_destino, id_periodo_origen]);
  };

  // Migrar usuarios
  const migrateUsuarios = () => {
      const sqlUsuarios = `
          INSERT INTO usuarios 
          (nombre_usuario, email, contraseña, estado, id_rol, telefono, direccion, fecha_nacimiento, genero, foto, id_periodo) 
          SELECT nombre_usuario, email, contraseña, estado, id_rol, telefono, direccion, fecha_nacimiento, genero, foto, ? 
          FROM usuarios WHERE id_periodo = ?`;
      return executeQuery(sqlUsuarios, [id_periodo_destino, id_periodo_origen]);
  };

  // Ejecutar todas las migraciones en secuencia
  const migrateAll = async () => {
      try {
          await migrateAlumnos();
          await migrateAsistencias();
          await migrateCursos();
          await migrateGrados();
          await migrateHorarios();
          await migrateInscripciones();
          await migratePagos();
          await migrateRecibos();
          await migrateReportes();
          await migrateRoles();
          await migrateSecciones();
          await migrateUsuarios();
          
          req.session.message = { type: 'success', content: 'Datos migrados exitosamente.' };
          res.redirect('/periodos');
        } catch (error) {
          console.error('Error migrando datos:', error);
          req.session.message = { type: 'error', content: 'Error al migrar los datos.' };
          res.redirect('/periodos');
        }
      };

  migrateAll();
});

//modulo control de pagos

// Ruta para pagos
// Ruta para pagos
// Ruta para pagos
app.get('/pagos', (req, res) => {
  // Consulta para obtener recibos y los nombres de los alumnos
  db.query(`
      SELECT r.id_recibo, r.numero_recibo, r.monto, r.estado, r.fecha_emision, r.fecha_pago, r.descripcion, 
             a.nombre AS nombre_alumno, 
             MONTH(r.fecha_emision) AS mes  -- Asegúrate de que esto obtenga el mes de la fecha de emisión
      FROM control r
      JOIN alumnos a ON r.id_alumno = a.id_alumno
  `, (err, recibos) => {
      if (err) {
          console.error(err);
          return res.status(500).send(err);
      }

      // Obtener la lista de alumnos para el formulario
      db.query(`SELECT id_alumno, nombre FROM alumnos`, (err, alumnos) => {
          if (err) {
              console.error(err);
              return res.status(500).send(err);
          }
          // Renderiza la vista con los recibos, la lista de alumnos y el arreglo de meses
          res.render('pagos/index', { recibos, alumnos, meses }); // Agregamos `meses`
      });
  });
});


// Ruta para crear un recibo
// Ruta para crear un recibo
// Definir un arreglo con los nombres de los meses
const meses = [
  'Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
  'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'
];

// Ruta para crear un recibo
app.post('/recibos/crear', (req, res) => {
  console.log('Datos recibidos:', req.body);
  const { numero_recibo, monto, estado, descripcion, id_alumno, fecha_pago } = req.body;

  // Obtener el nombre del mes actual
  const mes = meses[new Date().getMonth()]; // Obtener el nombre del mes

  // Inserta el recibo en la base de datos
  const queryInsert = `
      INSERT INTO control (numero_recibo, monto, estado, descripcion, fecha_emision, fecha_pago, id_alumno, mes) 
      VALUES (?, ?, ?, ?, NOW(), ?, ?, ?)
  `;

  const values = [numero_recibo, monto, estado, descripcion, fecha_pago || null, id_alumno, mes];

  db.query(queryInsert, values, (err, result) => {
      if (err) {
          console.error('Error al crear recibo:', err);
          return res.status(500).send('Error al crear el recibo');
      }

      // Después de insertar, hacemos una consulta para obtener los datos completos del recibo recién creado
      const id_recibo = result.insertId;
      const querySelect = `
          SELECT r.*, a.nombre AS nombre_alumno
          FROM control r
          JOIN alumnos a ON r.id_alumno = a.id_alumno
          WHERE r.id_recibo = ?
      `;
      db.query(querySelect, [id_recibo], (err, rows) => {
          if (err) {
              console.error('Error al obtener el recibo creado:', err);
              return res.status(500).send('Error al obtener el recibo creado');
          }

          // Devuelve los datos completos del recibo creado
          res.send({
              message: 'Recibo creado exitosamente',
              recibo: rows[0]  // Esto contiene todos los datos del recibo
          });
      });
  });
});

// Ruta para editar un recibo
// Ruta para editar un recibo
app.post('/recibos/editar', (req, res) => {
  console.log('Datos recibidos para editar:', req.body);
  const { id_recibo, numero_recibo, monto, estado, descripcion, id_alumno, fecha_pago } = req.body;

  // Calcula el nombre del mes a partir de la fecha de pago
  const mes = meses[new Date(fecha_pago).getMonth()]; // Obtener el nombre del mes

  // Actualiza el recibo en la base de datos
  const queryUpdate = `
      UPDATE control 
      SET numero_recibo = ?, monto = ?, estado = ?, descripcion = ?, fecha_pago = ?, id_alumno = ?, mes = ?
      WHERE id_recibo = ?
  `;

  const values = [numero_recibo, monto, estado, descripcion, fecha_pago || null, id_alumno, mes, id_recibo];

  db.query(queryUpdate, values, (err, result) => {
      if (err) {
          console.error('Error al editar el recibo:', err);
          return res.status(500).send('Error al editar el recibo');
      }

      if (result.affectedRows === 0) {
          return res.status(404).send('Recibo no encontrado');
      }

      // Después de actualizar, hacemos una consulta para obtener los datos actualizados del recibo
      const querySelect = `
          SELECT r.*, a.nombre AS nombre_alumno
          FROM control r
          JOIN alumnos a ON r.id_alumno = a.id_alumno
          WHERE r.id_recibo = ?
      `;
      db.query(querySelect, [id_recibo], (err, rows) => {
          if (err) {
              console.error('Error al obtener el recibo editado:', err);
              return res.status(500).send('Error al obtener el recibo editado');
          }

          if (rows.length === 0) {
              return res.status(404).send('Recibo no encontrado');
          }

          // Devuelve los datos actualizados del recibo
          res.send({
              message: 'Recibo editado exitosamente',
              recibo: rows[0]
          });
      });
  });
});

// Ruta para obtener un recibo por ID
app.get('/recibos/:id', (req, res) => {
  const id_recibo = req.params.id;

  const querySelect = `
      SELECT r.*, a.nombre AS nombre_alumno
      FROM control r
      JOIN alumnos a ON r.id_alumno = a.id_alumno
      WHERE r.id_recibo = ?
  `;
  db.query(querySelect, [id_recibo], (err, rows) => {
      if (err) {
          console.error('Error al obtener el recibo:', err);
          return res.status(500).send('Error al obtener el recibo');
      }
      if (rows.length === 0) {
          console.log('No se encontró ningún recibo con ID:', id_recibo);
          return res.status(404).send('Recibo no encontrado');
      }

      console.log('Recibo encontrado:', rows[0]); // Agregado para ver la respuesta
      res.send({
          recibo: rows[0]
      });
  });
});
// Ruta para eliminar un recibo
app.delete('/recibos/:id_recibo', (req, res) => {
  const id_recibo = req.params.id_recibo;

  // Lógica para eliminar el recibo de la base de datos
  db.query('DELETE FROM control WHERE id_recibo = ?', [id_recibo], (error, results) => {
      if (error) {
          return res.status(500).json({ success: false, message: 'Error al eliminar el recibo.' });
      }
      res.json({ success: true });
  });
});




//modulo de configuracion
// Obtener datos del usuario
app.get('/obtener-datos-usuario', (req, res) => {
  const usuarioId = req.session.user.id_usuario; // Asegúrate de que esta es la clave correcta en la sesión

  if (!usuarioId) {
      return res.status(401).json({ error: 'No estás autenticado' });
  }

  const query = 'SELECT nombre_usuario, email, telefono, direccion, genero FROM usuarios WHERE id_usuario = ?';
  
  db.query(query, [usuarioId], (err, results) => {
      if (err) {
          console.error('Error en la consulta:', err);
          return res.status(500).json({ error: 'Error al obtener datos' });
      }
      if (results.length === 0) {
          return res.status(404).json({ error: 'Usuario no encontrado' });
      }
      res.json(results[0]); // Envía los datos del usuario
  });
});

// Actualizar datos del usuario
app.post('/actualizar-datos-usuario', async (req, res) => {
  const { nombre_usuario, email, telefono, direccion, genero, nueva_contrasena } = req.body;
  const usuarioId = req.session.user.id_usuario; // Debe coincidir con el método anterior
  
  // Verificar si hay un usuario autenticado
  if (!usuarioId) {
      return res.status(401).json({ error: 'No estás autenticado' });
  }

  // Actualización de datos generales del usuario
  let query = 'UPDATE usuarios SET nombre_usuario = ?, email = ?, telefono = ?, direccion = ?, genero = ? WHERE id_usuario = ?';
  const values = [nombre_usuario, email, telefono, direccion, genero, usuarioId];

  try {
      // Si se proporcionó una nueva contraseña, actualízala también
      if (nueva_contrasena) {
          const hashedPassword = await bcrypt.hash(nueva_contrasena, 10); // Hashea la nueva contraseña
          query = 'UPDATE usuarios SET nombre_usuario = ?, email = ?, telefono = ?, direccion = ?, genero = ?, contraseña = ? WHERE id_usuario = ?';
          values.splice(5, 0, hashedPassword); // Insertar la contraseña hasheada antes del ID de usuario
      }

      // Ejecutar la consulta para actualizar los datos
      db.query(query, values, (err) => {
          if (err) {
              console.error('Error al actualizar datos:', err);
              return res.status(500).json({ error: 'Error al actualizar datos' });
          }
          res.json({ message: 'Datos actualizados correctamente' });
      });
  } catch (error) {
      console.error('Error al hashear la contraseña:', error);
      return res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});

//guardar datos
// Guardar datos
app.post('/guardar-configuracion', async (req, res) => {
  const { nombre_usuario, email, telefono, direccion, genero, nueva_contrasena } = req.body; // Cambia `nombre` a `nombre_usuario`
  const usuarioId = req.session.user.id_usuario;

  if (!usuarioId) {
      return res.status(401).json({ error: 'No estás autenticado' });
  }

  let query = 'UPDATE usuarios SET nombre_usuario = ?, email = ?, telefono = ?, direccion = ?, genero = ? WHERE id_usuario = ?';
  let values = [nombre_usuario, email, telefono, direccion, genero, usuarioId]; // Asegúrate de que coincida con el nombre

  try {
      // Si el usuario desea cambiar la contraseña, se debe actualizar el hash de la contraseña
      if (nueva_contrasena && nueva_contrasena.trim() !== '') {
          const hashedPassword = await bcrypt.hash(nueva_contrasena, 10);
          query = 'UPDATE usuarios SET nombre_usuario = ?, email = ?, telefono = ?, direccion = ?, genero = ?, contraseña = ? WHERE id_usuario = ?';
          values.splice(5, 0, hashedPassword); // Inserta el hash de la contraseña en la posición correcta
      }

      // Ejecutar la consulta
      db.query(query, values, (err, result) => {
          if (err) {
              console.error('Error al guardar la configuración:', err);
              return res.status(500).json({ error: 'Error al guardar la configuración' });
          }

          // Actualiza los datos del usuario en la sesión
          req.session.user.nombre_usuario = nombre_usuario; // Cambia `nombre` a `nombre_usuario`
          req.session.user.email = email;
          req.session.user.telefono = telefono;
          req.session.user.direccion = direccion;
          req.session.user.genero = genero;

          // Si la contraseña se cambió, asegúrate de no almacenarla en la sesión
          if (nueva_contrasena && nueva_contrasena.trim() !== '') {
              req.session.user.contraseña = hashedPassword; // Actualiza la contraseña en la sesión si es necesario
          }

          // Devolver la respuesta exitosa
          res.json({ message: 'Configuración guardada correctamente' });
      });
  } catch (error) {
      console.error('Error al procesar la solicitud:', error);
      return res.status(500).json({ error: 'Error al procesar la solicitud' });
  }
});


// Ruta para mostrar la página de reportes
// Ruta para mostrar la página de reportes
app.get('/reportes', (req, res) => {
  const reportesQuery = 'SELECT * FROM reportes ORDER BY id_reporte ASC, fecha_generacion DESC';
  const usuariosQuery = 'SELECT id_usuario, nombre_usuario FROM usuarios'; // Consulta para usuarios
  const periodosQuery = 'SELECT id_periodo, nombre_periodo FROM periodos_escolares'; // Consulta para periodos

  // Obtener reportes
  db.query(reportesQuery, (errorReportes, resultadosReportes) => {
      if (errorReportes) {
          console.error('Error al obtener los reportes:', errorReportes);
          return res.status(500).send('Error al obtener los reportes');
      }

      // Obtener usuarios
      db.query(usuariosQuery, (errorUsuarios, resultadosUsuarios) => {
          if (errorUsuarios) {
              console.error('Error al obtener los usuarios:', errorUsuarios);
              return res.status(500).send('Error al obtener los usuarios');
          }

          // Obtener periodos
          db.query(periodosQuery, (errorPeriodos, resultadosPeriodos) => {
              if (errorPeriodos) {
                  console.error('Error al obtener los periodos:', errorPeriodos);
                  return res.status(500).send('Error al obtener los periodos');
              }

              // Renderizar la vista con reportes, usuarios y periodos
              res.render('reportes/index', { 
                  reportes: resultadosReportes, 
                  usuarios: resultadosUsuarios, 
                  periodos: resultadosPeriodos 
              });
          });
      });
  });
});


// Ruta para generar un nuevo reporte
app.post('/reportes/generar', (req, res) => {
  const { estado_pago, id_usuario, id_periodo, tipo_reporte } = req.body; // Incluye tipo_reporte
  
  console.log('Datos recibidos para generar reporte:', req.body); // Para depuración
  
  // Validación del estado de pago
  const estadosValidos = ['pagado', 'pendiente', 'todos'];
  if (!estadosValidos.includes(estado_pago)) {
    return res.status(400).json({ error: 'Estado de pago no válido' });
  }
  
  // Mapeo de tipo_reporte a nombre completo
  const tipoReportes = {
    estudiantes_activos: "Reporte de Estudiantes Activos",
    estudiantes_inactivos: "Reporte de Estudiantes Inactivos",
    asistencia_fechas: "Reporte de Asistencia por Fechas",
    profesores_activos: "Reporte de Profesores Activos",
    profesores_inactivos: "Reporte de Profesores Inactivos",
    pagos: "Reporte de Pagos",
  };

  const fechaGeneracion = new Date();

  db.query(
      'INSERT INTO reportes (tipo_reporte, estado_pago, fecha_generacion, id_usuario, id_periodo) VALUES (?, ?, ?, ?, ?)', 
      [tipoReportes[tipo_reporte], estado_pago, fechaGeneracion, id_usuario, id_periodo], 
      (err, result) => {
          if (err) {
              console.error('Error al generar el reporte:', err);
              return res.status(500).json({ error: 'Error al generar el reporte' });
          }
          res.status(201).json({ message: 'Reporte generado exitosamente', id_reporte: result.insertId });
      }
  );
});

// Ruta para obtener los datos de un reporte específico en formato JSON
app.get('/reportes/datos/:id', (req, res) => {
  const { id } = req.params;

  console.log('ID recibido:', id); // Log del ID recibido

  // Verificar que el ID sea un número
  if (isNaN(id)) {
      return res.status(400).json({ success: false, error: 'El ID debe ser un número' });
  }

  // Consulta para obtener la información del reporte
  const reporteQuery = 'SELECT * FROM reportes WHERE id_reporte = ?';

  db.query(reporteQuery, [id], (error, resultadoReporte) => {
      if (error) {
          console.error('Error al obtener los datos del reporte:', error);
          return res.status(500).json({ success: false, error: 'Error al obtener los datos del reporte' });
      }

      console.log('Resultado de la consulta de reporte:', resultadoReporte); // Log de resultados

      if (resultadoReporte.length === 0) {
          return res.status(404).json({ success: false, error: 'Reporte no encontrado' });
      }

      const reporte = resultadoReporte[0];
      const tipoReporte = reporte.tipo_reporte;
      const fechaReporte = reporte.fecha; // Asegúrate de que la fecha esté disponible

      let consultaDatos;
      const params = [];

      // Definir consulta según el tipo de reporte
      switch (tipoReporte) {
          case 'Reporte de Alumnos Activos':
            consultaDatos = `
            SELECT a.id_alumno AS id_alumno, 
               a.nombre AS nombre_alumno, 
               a.apellido AS apellido_alumno,
               g.nombre_grado AS nombre_grado,
               a.seccion, 
               a.estado
        FROM alumnos AS a
        JOIN grados AS g ON a.id_grado = g.id_grado  
        WHERE a.estado = 'activo'
        `;
              break;
          case 'Reporte de Alumnos Inactivos':
            consultaDatos = `
        SELECT a.id_alumno AS id_alumno, 
               a.nombre AS nombre_alumno, 
               a.apellido AS apellido_alumno,
               g.nombre_grado AS nombre_grado,
               a.seccion, 
               a.estado
        FROM alumnos AS a
        JOIN grados AS g ON a.id_grado = g.id_grado  
        WHERE a.estado = 'inactivo'
    `;
    break;
              break;
          case 'Reporte de Asistencia':
              consultaDatos = `
                  SELECT a.nombre_alumno, a.apellido_alumno,
                      SUM(CASE WHEN asis.estado = 'presente' THEN 1 ELSE 0 END) AS veces_presente,
                      SUM(CASE WHEN asis.estado = 'tarde' THEN 1 ELSE 0 END) AS veces_tarde,
                      SUM(CASE WHEN asis.estado = 'ausente' THEN 1 ELSE 0 END) AS veces_ausente
                  FROM asistencias AS asis
                  JOIN alumnos AS a ON asis.id_alumno = a.id_alumno
                  WHERE asis.fecha = ?
                  GROUP BY a.id_alumno
              `;
              params.push(fechaReporte); // Agrega la fecha al array de parámetros
              break;
              case 'Reporte de Asistencia de Profesores':
        consultaDatos = `
          SELECT p.nombre,
              SUM(CASE WHEN asis.estado = 'presente' THEN 1 ELSE 0 END) AS veces_presente,
              SUM(CASE WHEN asis.estado = 'tarde' THEN 1 ELSE 0 END) AS veces_tarde,
              SUM(CASE WHEN asis.estado = 'ausente' THEN 1 ELSE 0 END) AS veces_ausente
          FROM asistencias AS asis
          JOIN profesores AS p ON asis.id_profesor = p.id_profesor
          WHERE asis.fecha = ?
          GROUP BY p.id_profesor
        `;
        params.push(fechaReporte); // Agrega la fecha como parámetro
        break;
          case 'Reporte de Pagos':
            consultaDatos = `
            SELECT c.numero_recibo, 
                   c.monto, 
                   c.estado, 
                   DATE_FORMAT(c.fecha_emision, '%Y-%m-%d') AS fecha_emision, 
                   DATE_FORMAT(c.fecha_pago, '%Y-%m-%d') AS fecha_pago,
                   c.descripcion,
                   a.nombre
            FROM control AS c
            JOIN alumnos AS a ON c.id_alumno = a.id_alumno
            WHERE c.estado = ?
        `;
              params.push(reporte.estado_pago); // Agrega el estado de pago
              break;
          default:
              console.error('Tipo de reporte no válido:', tipoReporte); // Log de error
              return res.status(400).json({ success: false, error: 'Tipo de reporte no válido' });
      }

      console.log('Consulta de datos:', consultaDatos, 'Con parámetros:', params); // Log de consulta

      // Consulta los datos del reporte
      db.query(consultaDatos, params, (errorDatos, datos) => {
          if (errorDatos) {
              console.error('Error al obtener los datos del reporte:', errorDatos);
              return res.status(500).json({ success: false, error: 'Error al obtener los datos del reporte' });
          }

          res.json({ success: true, datos });
      });
  });
});

//vista profesor
// Ruta para mostrar el formulario de calificaciones
app.get('/calificaciones', async (req, res) => {
  // Verifica si el usuario está autenticado
  if (!req.session.user) {
    return res.status(401).send("Acceso no autorizado.");
  }
  
  const idProfesor = req.session.user.id_usuario;

  try {
    const cursosYAlumnos = await obtenerCursosYAlumnosPorProfesor(idProfesor);
    res.render('calificaciones/index', { cursosYAlumnos });
  } catch (err) {
    console.error("Error al obtener datos:", err);
    res.status(500).send("Error al obtener datos");
  }
});


// Ruta para obtener alumnos por curso
app.get('/obtener_alumnos_por_profesor', async (req, res) => {
  // Verifica si el usuario está autenticado
  if (!req.session.user) {
    return res.status(401).send("Acceso no autorizado.");
  }
  
  const idProfesor = req.session.user.id_usuario;
  const cursoId = req.query.curso_id;

  try {
    const alumnos = await obtenerAlumnosPorCursoYProfesor(idProfesor, cursoId);
    res.json(alumnos);
  } catch (err) {
    console.error("Error al obtener datos:", err);
    res.status(500).send("Error al obtener datos");
  }
});


// Función para guardar calificaciones
app.post('/guardar_calificaciones', async (req, res) => {
  if (!req.session.user) {
      return res.status(401).send("Acceso no autorizado.");
  }

  const calificaciones = req.body.calificaciones; // Las calificaciones por alumno
  const id_curso = req.body.id_curso; // ID del curso

  try {
      await db.beginTransaction();

      for (const id_alumno in calificaciones) {
          const { bimestre1, bimestre2, bimestre3, bimestre4, id_calificacion } = calificaciones[id_alumno]; // Incluye id_calificacion
          const suma = parseFloat(bimestre1 || 0) + parseFloat(bimestre2 || 0) + parseFloat(bimestre3 || 0) + parseFloat(bimestre4 || 0);
          const cantidad = (bimestre1 ? 1 : 0) + (bimestre2 ? 1 : 0) + (bimestre3 ? 1 : 0) + (bimestre4 ? 1 : 0);
          const promedio = cantidad > 0 ? (suma / cantidad) : 0;

          // Consulta SQL para insertar o actualizar
          const sql = `
              INSERT INTO calificaciones (id_calificacion, id_alumno, id_curso, bimestre_I, bimestre_II, bimestre_III, bimestre_IV, promedio)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              ON DUPLICATE KEY UPDATE 
                  bimestre_I = VALUES(bimestre_I),
                  bimestre_II = VALUES(bimestre_II),
                  bimestre_III = VALUES(bimestre_III),
                  bimestre_IV = VALUES(bimestre_IV),
                  promedio = VALUES(promedio)`;

          await db.query(sql, [id_calificacion, id_alumno, id_curso, bimestre1, bimestre2, bimestre3, bimestre4, promedio]);
      }

      await db.commit();
      res.send({ message: "Calificaciones guardadas exitosamente." });
  } catch (error) {
      await db.rollback();
      console.error("Error al guardar las calificaciones:", error);
      res.status(500).send("Error al guardar las calificaciones.");
  }
});

// Ruta para obtener calificaciones de un alumno
app.get('/api/calificaciones/:idAlumno', (req, res) => {
  const idAlumno = req.params.idAlumno;

  const query = `
      SELECT a.nombre AS nombre_alumno, 
             a.apellido AS apellido_alumno, 
             g.nombre_grado AS grado_alumno, 
             c.nombre_curso, 
             p.nombre AS nombre_profesor, 
             cal.bimestre_I AS bimestre1, 
             cal.bimestre_II AS bimestre2, 
             cal.bimestre_III AS bimestre3, 
             cal.bimestre_IV AS bimestre4, 
             cal.promedio
      FROM calificaciones cal
      JOIN cursos c ON c.id_curso = cal.id_curso
      JOIN alumnos a ON a.id_alumno = cal.id_alumno
      JOIN grados g ON a.id_grado = g.id_grado 
      JOIN profesores p ON c.id_profesor = p.id_profesor  
      WHERE cal.id_alumno = ?`;

  db.query(query, [idAlumno], (error, results) => {
      if (error) {
          console.error('Error en la consulta de la base de datos:', error);
          return res.status(500).json({ error: 'Error en la consulta de la base de datos' });
      }

      if (!Array.isArray(results) || results.length === 0) {
          return res.status(404).json({ error: 'No se encontraron datos para el alumno' });
      }

      res.json(results);
  });
});

// Función para agregar o actualizar calificaciones
function agregarOActualizarCalificacion(calificacion) {
  const { id_estudiante, id_curso, nota } = calificacion;

  const query = `
      INSERT INTO calificaciones (id_estudiante, id_curso, nota)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE nota = ?;
  `;

  connection.query(query, [id_estudiante, id_curso, nota, nota], (error, results) => {
      if (error) throw error;
      console.log(results);
  });
}

// Mantén las funciones para obtener cursos y alumnos igual que en tu módulo de asistencia
async function obtenerAlumnosPorCursoYProfesor(idProfesor, cursoId) {
  const query = `
      SELECT 
          a.id_alumno, 
          a.nombre AS nombre, 
          a.apellido AS apellido, 
          c.nombre_curso, 
          g.nombre_grado
      FROM alumnos a
      JOIN inscripciones i ON a.id_alumno = i.id_alumno
      JOIN cursos c ON i.id_curso = c.id_curso
      JOIN grados g ON c.id_grado = g.id_grado
      WHERE c.id_profesor = ? AND c.id_curso = ?`;

  return new Promise((resolve, reject) => {
    db.query(query, [idProfesor, cursoId], (err, results) => {
      if (err) {
        console.error("Error en la consulta:", err.message);
        return reject(err);
      }
      resolve(results);
    });
  });
}
// Función para obtener cursos y alumnos asignados a un profesor (mantenla igual)
async function obtenerCursosYAlumnosPorProfesor(idProfesor) {
  const queryCursos = `
      SELECT 
          c.id_curso, 
          c.nombre_curso, 
          g.nombre_grado 
      FROM cursos c
      JOIN grados g ON c.id_grado = g.id_grado
      WHERE c.id_profesor = ?`;

  const queryAlumnos = `
      SELECT 
          a.id_alumno, 
          a.nombre AS nombre_alumno,
          i.id_curso
      FROM alumnos a
      JOIN inscripciones i ON a.id_alumno = i.id_alumno
      JOIN cursos c ON i.id_curso = c.id_curso
      WHERE c.id_profesor = ?`;

  return new Promise(async (resolve, reject) => {
    try {
      const [cursos, alumnos] = await Promise.all([
        new Promise((res, rej) => db.query(queryCursos, [idProfesor], (err, results) => err ? rej(err) : res(results))),
        new Promise((res, rej) => db.query(queryAlumnos, [idProfesor], (err, results) => err ? rej(err) : res(results))),
      ]);

      const cursosConAlumnos = cursos.map(curso => {
        return {
          ...curso,
          alumnos: alumnos.filter(alumno => alumno.id_curso === curso.id_curso),
        };
      });

      resolve(cursosConAlumnos);
    } catch (error) {
      console.error("Error en la consulta:", error.message);
      reject(error);
    }
  });
}

//modulo de asistencia alumnos
app.get('/asistencia_alumnos', async (req, res) => {
  // Verifica si el usuario está autenticado
  if (!req.session.user) {
    return res.status(401).send("Acceso no autorizado.");
  }
  
  const idProfesor = req.session.user.id_usuario;

  try {
    const cursosYAlumnos = await obtenerCursosYAlumnosPorProfesor(idProfesor);
    res.render('asistencia_alumnos/index', { cursosYAlumnos });
  } catch (err) {
    console.error("Error al obtener datos:", err);
    res.status(500).send("Error al obtener datos");
  }
});

app.get('/obtener_alumnos_por_profesor', async (req, res) => {
  // Verifica si el usuario está autenticado
  if (!req.session.user) {
    return res.status(401).send("Acceso no autorizado.");
  }
  
  const idProfesor = req.session.user.id_usuario; // Obtener ID del profesor
  const cursoId = req.query.curso_id; // Obtener el ID del curso desde la consulta

  try {
    // Obtener alumnos por curso y profesor
    const alumnos = await obtenerAlumnosPorCursoYProfesor(idProfesor, cursoId);
    res.json(alumnos);
  } catch (err) {
    console.error("Error al obtener datos:", err);
    res.status(500).send("Error al obtener datos");
  }
});

// Función para obtener alumnos por curso y profesor
async function obtenerAlumnosPorCursoYProfesor(idProfesor, cursoId) {
  const query = `
      SELECT 
          a.id_alumno, 
          a.nombre AS nombre, 
          a.apellido AS apellido, 
          c.nombre_curso, 
          g.nombre_grado
      FROM alumnos a
      JOIN inscripciones i ON a.id_alumno = i.id_alumno
      JOIN cursos c ON i.id_curso = c.id_curso
      JOIN grados g ON c.id_grado = g.id_grado
      WHERE c.id_profesor = ? AND c.id_curso = ?`;

  return new Promise((resolve, reject) => {
    db.query(query, [idProfesor, cursoId], (err, results) => {
      if (err) {
        console.error("Error en la consulta:", err.message);
        return reject(err);
      }
      resolve(results);
    });
  });
}


// Función para obtener cursos y alumnos asignados a un profesor
async function obtenerCursosYAlumnosPorProfesor(idProfesor) {
  const queryCursos = `
      SELECT 
          c.id_curso, 
          c.nombre_curso, 
          g.nombre_grado 
      FROM cursos c
      JOIN grados g ON c.id_grado = g.id_grado
      WHERE c.id_profesor = ?`;

  const queryAlumnos = `
      SELECT 
          a.id_alumno, 
          a.nombre AS nombre_alumno,
          i.id_curso
      FROM alumnos a
      JOIN inscripciones i ON a.id_alumno = i.id_alumno
      JOIN cursos c ON i.id_curso = c.id_curso
      WHERE c.id_profesor = ?`;

  return new Promise(async (resolve, reject) => {
    try {
      const [cursos, alumnos] = await Promise.all([
        new Promise((res, rej) => db.query(queryCursos, [idProfesor], (err, results) => err ? rej(err) : res(results))),
        new Promise((res, rej) => db.query(queryAlumnos, [idProfesor], (err, results) => err ? rej(err) : res(results))),
      ]);

      const cursosConAlumnos = cursos.map(curso => {
        return {
          ...curso,
          alumnos: alumnos.filter(alumno => alumno.id_curso === curso.id_curso),
        };
      });

      resolve(cursosConAlumnos);
    } catch (error) {
      console.error("Error en la consulta:", error.message);
      reject(error);
    }
  });
}

app.post('/guardar_asistencia', (req, res) => {
  const { fecha_asistencia, asistencia } = req.body;

  // Verifica que el objeto asistencia no esté vacío
  if (!asistencia || Object.keys(asistencia).length === 0) {
      return res.status(400).json({ message: 'El objeto asistencia no puede estar vacío.' });
  }

  const query = "INSERT INTO asistencias_alumnos (id_alumno, fecha, estado) VALUES (?, ?, ?)";
  const queries = [];

  // Prepara las consultas para cada alumno
  for (const [id_alumno, estado] of Object.entries(asistencia)) {
      const promise = new Promise((resolve, reject) => {
          db.query(query, [id_alumno, fecha_asistencia, estado], (error) => {
              if (error) {
                  console.error('Error al insertar asistencia:', error);
                  return reject(error);
              }
              resolve();
          });
      });
      queries.push(promise);
  }

  // Ejecuta todas las consultas
  Promise.all(queries)
      .then(() => {
          res.status(200).json({ message: 'Asistencias guardadas' });
      })
      .catch(error => {
          console.error('Error al guardar asistencias:', error);
          res.status(500).json({ message: 'Error al guardar asistencias' });
      });
});


//modulo de horarios
function obtenerHorarioPorProfesor(idProfesor) {
  return new Promise((resolve, reject) => {
      const query = `
          SELECT h.id_horario, h.dia_semana, h.hora_inicio, h.hora_fin, 
                 c.nombre_curso AS nombre_curso, g.nombre_grado AS nombre_grado, s.nombre_seccion AS nombre_seccion
          FROM horarios h
          JOIN cursos c ON h.id_curso = c.id_curso
          JOIN grados g ON h.id_grado = g.id_grado
          JOIN secciones s ON h.id_seccion = s.id_seccion
          WHERE h.id_profesor = ?`;

      db.query(query, [idProfesor], (err, results) => {
          if (err) {
              console.error('Error al obtener horarios:', err);
              return reject(err);
          }
          resolve(results);
      });
  });
}
// Ruta para mostrar el horario del profesor
app.get('/horarios_profesor', verificarAutenticacion, async (req, res) => {
  const idProfesor = req.session.user.id_usuario; // Usamos el ID del profesor desde la sesión
  try {
      const horarios = await obtenerHorarioPorProfesor(idProfesor); // Método para obtener horarios
      res.render('horarios_profesor/index', { horarios, user: req.session.user }); // Pasar los datos del usuario a la vista
  } catch (error) {
      console.error('Error al obtener los horarios:', error);
      res.status(500).send('Error al obtener los horarios');
  }
});

// Middleware para verificar si el usuario está autenticado
function verificarAutenticacion(req, res, next) {
  if (req.session.user && req.session.user.rol === 'profesor') {
      return next();
  }
  res.redirect('/login-profesor'); // Redirige si no está autenticado o no es un profesor
}


// Rutas
const authRouter = require('./routes/auth');
const cursosRouter = require('./routes/cursos'); // Asegúrate de tener este require
app.use('/', authRouter);
app.use('/estudiantes', estudiantesRouter);
app.use('/cursos', cursosRouter);


app.get('/roles', (req, res) => {
  res.render('roles');
});


app.get('/usuarios', (req, res) => {
  res.render('usuarios/index'); // Solo renderiza el contenido del CRUD
});

app.get('/login-profesor', (req, res) => {
  res.render('profesores/login-profesor');
});

app.get('/cursos', (req, res) => {
  res.render('cursos', { userName: 'Nombre de Usuario' }); // Renderiza la vista cursos.ejs
});

app.get('/profesores', (req, res) => {
  res.render('profesores', { userName: 'Nombre de Usuario' }); // Renderiza la vista profesores.ejs
});

app.get('/reportes', (req, res) => {
  res.render('reportes', { userName: 'Nombre de Usuario' }); // Renderiza la vista reportes.ejs
});

app.get('/calificaciones', (req, res) => {
  res.render('calificaciones', { userName: 'Nombre de Usuario' }); // Renderiza la vista calificaciones.ejs
});

app.get('/recibos', (req, res) => {
  res.render('recibos', { userName: 'Nombre de Usuario' }); // Renderiza la vista recibos.ejs
});

app.get('/lista-recibos', (req, res) => {
  res.render('lista-recibos', { userName: 'Nombre de Usuario' }); // Renderiza la vista lista-recibos.ejs
});

app.get('/asistencia', (req, res) => {
  res.render('asistencia', { userName: 'Nombre de Usuario' }); // Renderiza la vista asistencia.ejs
});

app.get('/tareas', (req, res) => {
  res.render('tareas', { userName: 'Nombre de Usuario' }); // Renderiza la vista tareas.ejs
});

app.get('/comentarios', (req, res) => {
  res.render('comentarios', { userName: 'Nombre de Usuario' }); // Renderiza la vista comentarios.ejs
});

app.get('/logout', (req, res) => {
  // Código para cerrar sesión y redirigir al login, por ejemplo
  res.redirect('/login');
});

// Ruta para la portada
app.get('/principal', (req, res) => {
  res.render('principal'); // Renderiza principal.ejs
});

// Ruta para "/page"
app.get('/page', (req, res) => {
  res.render('page'); // Renderiza 'page.ejs' desde la carpeta 'views'
});

// Ruta para la página de contacto
app.get('/contacto', (req, res) => {
  res.render('contacto');
});

// Ruta para la página sobre nosotros
app.get('/sobre', (req, res) => {
  res.render('sobre');
});

// Ruta para el álbum de fotos
app.get('/album', (req, res) => {
  res.render('album'); // Renderiza el archivo album.ejs en la carpeta views
});

// Ruta para Preprimaria
app.get('/preprimaria', (req, res) => {
  res.render('preprimaria');
});

// Ruta para Primaria
app.get('/primaria', (req, res) => {
  res.render('primaria');
});

// Ruta para Básico
app.get('/basico', (req, res) => {
  res.render('basico');
});

// Ruta para Diversificado
app.get('/diversificado', (req, res) => {
  res.render('diversificado');
});

app.get('/usuarios', (req, res) => {
  res.render('usuarios/index'); // Renderiza solo el contenido del CRUD sin recargar toda la página
});


// Ruta para servir la nueva página principal
app.get('/home', (req, res) => {
  res.render('home');
});

// Ruta para el dashboard de administrador
app.get('/dashboard', (req, res) => {
  res.render('dashboard', { roleName: 'Administrador', userName: req.session.nombre });
});

// Ruta para el dashboard de profesor
app.get('/dashboard-profesor', (req, res) => {
  res.render('dashboard-profesor', { roleName: 'Profesor', userName: req.session.nombre });
});

// Configurar la ruta para la página de recuperación de contraseña del profesor
app.get('/reset-profesor', (req, res) => {
  res.render('reset-profesor'); // Renderiza el archivo reset-profesor.ejs
});

app.get('/usuarios', (req, res) => {
  const userId = req.session.user ? req.session.user.id_usuario : null; // Obtener el ID del usuario de la sesión

  if (!userId) {
    return res.redirect('/login'); // Redirige al usuario si no está autenticado
  }

  // Cambia a `id_usuario` en la consulta
  db.query('SELECT * FROM usuarios WHERE id_usuario = ?', [userId], (error, results) => {
    if (error) {
      console.error('Error en la consulta: ', error);
      return res.status(500).send('Error en el servidor');
    }

    if (results.length === 0) {
      return res.status(404).send('Usuario no encontrado');
    }

    const user = results[0];
    console.log('Usuario:', user); // Verifica el contenido de `user`
    
    // Asegúrate de pasar 'user' a la vista
    res.render('usuarios/index', { user });
  });
});


// Middleware para pasar la información del usuario a todas las vistas
app.use((req, res, next) => {
  if (req.session.user) {
    // Si hay un usuario logueado, pasamos sus datos a las vistas
    res.locals.user = req.session.user;
  } else {
    res.locals.user = null; // Si no hay sesión, pasamos null
  }
  next();
});



// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});