const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mysql = require('mysql');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const cors = require('cors');
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
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


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
        res.redirect('/dashboard'); // Asegúrate de que esta ruta esté correcta
      });
    });
  });
});



// En la vista de login
app.get('/login', (req, res) => {
  const error = req.session.error;
  delete req.session.error;
  res.render('login', { error });
});

// Ruta GET para mostrar el formulario de login de profesor
app.get('/login-profesor', (req, res) => {
  const error = req.session.error;
  delete req.session.error; // Elimina el error de la sesión después de mostrarlo
  res.render('profesores/login-profesor', { error }); // Pasar el error a la vista
});


// En la vista del dashboard
app.get('/dashboard', (req, res) => {
  const success = req.session.success;
  delete req.session.success;
  res.render('dashboard', { success, user: req.session.user });
});


// Ruta para mostrar el dashboard de profesor
app.get('/dashboard-profesor', (req, res) => {
  // Verifica si el usuario está autenticado
  if (!req.session.user) {
    return res.redirect('/login-profesor'); // Redirige al login si no está autenticado
  }

  // Renderiza la vista del dashboard de profesor
  res.render('dashboard-profesor', { user: req.session.user });
});

// Ruta para el login de profesor
// Ruta para el login de profesor
app.post('/login-profesor', (req, res) => {
  const { email, contraseña } = req.body;

  // Verificación de campos vacíos
  if (!email || !contraseña) {
    req.session.error = 'Todos los campos son requeridos';
    return res.redirect('/login-profesor');
  }

  const query = 'SELECT id_usuario, nombre_usuario, contraseña, id_rol, foto FROM usuarios WHERE email = ? AND estado = \'activo\'';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Error en la consulta de usuario:', err);
      req.session.error = 'Error en el servidor';
      return res.redirect('/login-profesor');
    }

    if (results.length === 0) {
      req.session.error = 'Email, contraseña incorrectos o usuario inactivo';
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

        req.session.user = {
          id_usuario: usuario.id_usuario,
          nombre_usuario: usuario.nombre_usuario,
          rol: roleResult[0].nombre_rol,
          profilePicture: usuario.foto || '/path/to/default/profile.jpg' // Cambia esta ruta
        };

        req.session.success = 'Bienvenido, has iniciado sesión exitosamente';
        res.redirect('/dashboard-profesor'); // Asegúrate de que esta ruta esté correcta
      });
    });
  });
});


// módulo usuarios
// Ruta para obtener usuarios con paginación
app.get('/api/usuarios', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const offset = (page - 1) * limit;

  const query = `SELECT * FROM usuarios LIMIT ? OFFSET ?`;
  db.query(query, [limit, offset], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });

      // Contar el total de usuarios para paginación
      db.query('SELECT COUNT(*) AS count FROM usuarios', (err, countResult) => {
          if (err) return res.status(500).json({ error: err.message });

          res.json({
              users: results,
              totalPages: Math.ceil(countResult[0].count / limit)
          });
      });
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
app.delete('/api/usuarios/:id', (req, res) => {
  const id = req.params.id;

  // Primero eliminar de la tabla profesores
  const sqlProfesor = 'DELETE FROM profesores WHERE id_profesor = ?';
  db.query(sqlProfesor, [id], (err) => {
      if (err) return res.status(500).json({ error: err.message });

      // Luego eliminar de la tabla usuarios
      const sqlUsuario = 'DELETE FROM usuarios WHERE id_usuario = ?';
      db.query(sqlUsuario, [id], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: 'Usuario y profesor eliminados exitosamente' });
      });
  });
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
// En tu archivo server.js o similar
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


// Eliminar un alumno
app.delete('/alumnos/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM alumnos WHERE id_alumno=?', [id], (err) => {
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

  db.query(
    `UPDATE alumnos 
     SET nombre=?, apellido=?, fecha_nacimiento=?, email=?, telefono=?, seccion=?, estado=?, id_grado=?, 
         nombre_padre=?, telefono_padre=?, correo_padre=?, 
         nombre_madre=?, telefono_madre=?, correo_madre=? 
     WHERE id_alumno=?`, 
    [
      nombre, apellido, fecha_nacimiento, email, telefono, seccion, estado, id_grado, 
      nombre_padre, telefono_padre, correo_padre, 
      nombre_madre, telefono_madre, correo_madre, 
      id
    ], 
    (err) => {
      if (err) {
        console.error(err); // Imprimir el error en consola
        return res.status(500).send(err);
      }
      res.send('Alumno actualizado');
    }
  );
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
      SELECT c.*, g.nombre_grado, p.nombre AS nombre_profesor 
      FROM cursos c 
      JOIN grados g ON c.id_grado = g.id_grado 
      JOIN profesores p ON c.id_profesor = p.id_profesor
  `;
  db.query(sql, (err, cursos) => {
      if (err) return res.status(500).send(err);

      const gradosSql = 'SELECT * FROM grados';
      const profesoresSql = 'SELECT * FROM profesores';

      db.query(gradosSql, (err, grados) => {
          if (err) return res.status(500).send(err);
          db.query(profesoresSql, (err, profesores) => {
              if (err) return res.status(500).send(err);

              const message = req.session.message;  // Obtener el mensaje de la sesión
              req.session.message = null;  // Limpiar el mensaje de la sesión

              res.render('cursos/index', { cursos, grados, profesores, message });  // Pasar el mensaje a la vista
          });
      });
  });
});


// Ruta para crear un nuevo curso
app.post('/cursos/crear', (req, res) => {
  const { nombre_curso, descripcion, id_grado, id_profesor, estado } = req.body;
  const sql = 'INSERT INTO cursos (nombre_curso, descripcion, id_grado, id_profesor, estado) VALUES (?, ?, ?, ?, ?)';
  db.query(sql, [nombre_curso, descripcion, id_grado, id_profesor, estado], (err) => {
      if (err) {
          req.session.message = { type: 'danger', content: 'Error al crear el curso.' };
          return res.redirect('/cursos');
      }
      req.session.message = { type: 'success', content: 'Curso creado exitosamente.' };
      res.redirect('/cursos');
  });
});

// Ruta para editar un curso
app.post('/cursos/editar/:id', (req, res) => {
  const { id } = req.params;
  const { nombre_curso, descripcion, id_grado, id_profesor, estado } = req.body;
  const sql = 'UPDATE cursos SET nombre_curso = ?, descripcion = ?, id_grado = ?, id_profesor = ?, estado = ? WHERE id_curso = ?';
  db.query(sql, [nombre_curso, descripcion, id_grado, id_profesor, estado, id], (err) => {
      if (err) {
          req.session.message = { type: 'danger', content: 'Error al editar el curso.' };
          return res.redirect('/cursos');
      }
      req.session.message = { type: 'success', content: 'Curso editado exitosamente.' };
      res.redirect('/cursos');
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
app.get('/horarios', (req, res) => {
  const queryHorarios = `
        SELECT 
            h.*, 
            c.nombre_curso, 
            p.nombre AS nombre_profesor,
            IFNULL(GROUP_CONCAT(DISTINCT g.nombre_grado), 'Sin grado asignado') AS nombre_grado, 
            IFNULL(GROUP_CONCAT(DISTINCT s.nombre_seccion), 'Sin sección asignada') AS nombre_seccion
        FROM 
            horarios h
        INNER JOIN 
            cursos c ON h.id_curso = c.id_curso
        LEFT JOIN 
            profesores p ON h.id_profesor = p.id_profesor
        LEFT JOIN 
            horario_grados hg ON h.id_horario = hg.id_horario
        LEFT JOIN 
            grados g ON hg.id_grado = g.id_grado
        LEFT JOIN 
            horario_secciones hs ON h.id_horario = hs.id_horario
        LEFT JOIN 
            secciones s ON hs.id_seccion = s.id_seccion
        GROUP BY 
            h.id_horario;
    `;
  const queryCursos = `SELECT * FROM cursos`;
  const queryProfesores = `SELECT * FROM profesores`;
  const queryGrados = `SELECT * FROM grados`;
  const querySecciones = `SELECT * FROM secciones`;

  // Obtener los cursos
  db.query(queryCursos, (errorCursos, cursos) => {
    if (errorCursos) {
      console.error('Error al obtener los cursos:', errorCursos);
      return res.status(500).send('Error en el servidor');
    }

    // Obtener los profesores
    db.query(queryProfesores, (errorProfesores, profesores) => {
      if (errorProfesores) {
        console.error('Error al obtener los profesores:', errorProfesores);
        return res.status(500).send('Error en el servidor');
      }

      // Obtener los grados
      db.query(queryGrados, (errorGrados, grados) => {
        if (errorGrados) {
          console.error('Error al obtener los grados:', errorGrados);
          return res.status(500).send('Error en el servidor');
        }

        // Obtener las secciones
        db.query(querySecciones, (errorSecciones, secciones) => {
          if (errorSecciones) {
            console.error('Error al obtener las secciones:', errorSecciones);
            return res.status(500).send('Error en el servidor');
          }

          // Obtener los horarios
          db.query(queryHorarios, (errorHorarios, horarios) => {
            if (errorHorarios) {
              console.error('Error al obtener los horarios:', errorHorarios);
              return res.status(500).send('Error en el servidor');
            }

            // Renderizar la vista con los datos obtenidos
            res.render('horarios/index', {
              horarios,
              cursos,
              profesores,
              grados,
              secciones
            });
          });
        });
      });
    });
  });
});


// Ruta para mostrar el formulario de agregar un nuevo horario
app.get('/horarios/agregar', (req, res) => {
  const queryCursos = `SELECT * FROM cursos`;
  const queryProfesores = `SELECT * FROM profesores`;
  const queryGrados = `SELECT * FROM grados`; // Consulta para grados
  const querySecciones = `SELECT * FROM secciones`; // Consulta para secciones

  // Ejecutar la consulta de cursos
  db.query(queryCursos, (errorCursos, cursos) => {
    if (errorCursos) {
      console.error('Error al obtener los cursos:', errorCursos);
      return res.status(500).send('Error al obtener los cursos');
    }

    // Ejecutar la consulta de profesores
    db.query(queryProfesores, (errorProfesores, profesores) => {
      if (errorProfesores) {
        console.error('Error al obtener los profesores:', errorProfesores);
        return res.status(500).send('Error al obtener los profesores');
      }

      // Ejecutar la consulta de grados
      db.query(queryGrados, (errorGrados, grados) => {
        if (errorGrados) {
          console.error('Error al obtener los grados:', errorGrados);
          return res.status(500).send('Error al obtener los grados');
        }

        // Ejecutar la consulta de secciones
        db.query(querySecciones, (errorSecciones, secciones) => {
          if (errorSecciones) {
            console.error('Error al obtener las secciones:', errorSecciones);
            return res.status(500).send('Error al obtener las secciones');
          }

          // Renderizar la vista 'agregar' con los datos obtenidos
          res.render('horarios/agregar', {
            cursos,
            profesores,
            grados,
            secciones
          });
        });
      });
    });
  });
});

// Ruta para agregar un nuevo horario
app.post('/horarios/agregar', (req, res) => {
  const { id_curso, dia_semana, hora_inicio, hora_fin, id_profesor, grados, secciones } = req.body;

  db.query('INSERT INTO horarios (id_curso, dia_semana, hora_inicio, hora_fin, id_profesor) VALUES (?, ?, ?, ?, ?)', 
  [id_curso, dia_semana, hora_inicio, hora_fin, id_profesor], 
  (error, results) => {
    if (error) {
      console.error('Error al agregar el horario:', error);
      return res.status(500).send('Error en el servidor');
    }

    const id_horario = results.insertId; // Obtener el ID del nuevo horario

    // Insertar grados asociados
    const gradoValues = (grados || []).map(grado => [id_horario, grado]);
    if (gradoValues.length > 0) {
      db.query('INSERT INTO horario_grados (id_horario, id_grado) VALUES ?', [gradoValues], (err) => {
        if (err) {
          console.error('Error al agregar grados:', err);
          return res.status(500).send('Error al agregar grados');
        }
      });
    }

    // Insertar secciones asociadas
    const seccionValues = (secciones || []).map(seccion => [id_horario, seccion]);
    if (seccionValues.length > 0) {
      db.query('INSERT INTO horario_secciones (id_horario, id_seccion) VALUES ?', [seccionValues], (err) => {
        if (err) {
          console.error('Error al agregar secciones:', err);
          return res.status(500).send('Error al agregar secciones');
        }
        res.redirect('/horarios'); // Redirigir a la lista de horarios después de agregar
      });
    } else {
      res.redirect('/horarios'); // Si no hay secciones, redirigir de todos modos
    }
  });
});

app.post('/horarios/editar', (req, res) => {
  const { id_horario, id_curso, dia_semana, hora_inicio, hora_fin, id_profesor, edit_grados, edit_secciones } = req.body;

  const sql = `
      UPDATE horarios
      SET id_curso = ?, dia_semana = ?, hora_inicio = ?, hora_fin = ?, id_profesor = ?
      WHERE id_horario = ?
  `;

  db.query(sql, [id_curso, dia_semana, hora_inicio, hora_fin, id_profesor, id_horario], (err) => {
      if (err) {
          console.error(err);
          return res.status(500).send('Error al actualizar el horario');
      }

      // Eliminar asociaciones existentes
      db.query('DELETE FROM horario_grados WHERE id_horario = ?', [id_horario], (err) => {
          if (err) {
              console.error('Error al eliminar asociaciones de grados:', err);
              return res.status(500).send('Error al eliminar asociaciones de grados');
          }

          db.query('DELETE FROM horario_secciones WHERE id_horario = ?', [id_horario], (err) => {
              if (err) {
                  console.error('Error al eliminar asociaciones de secciones:', err);
                  return res.status(500).send('Error al eliminar asociaciones de secciones');
              }

              // Insertar nuevas asociaciones de grados
              const gradoValues = (edit_grados || []).map(grado => [id_horario, grado]);
              if (gradoValues.length > 0) {
                  db.query('INSERT INTO horario_grados (id_horario, id_grado) VALUES ?', [gradoValues], (err) => {
                      if (err) {
                          console.error('Error al agregar nuevos grados:', err);
                          return res.status(500).send('Error al agregar nuevos grados');
                      }
                  });
              }

              // Insertar nuevas asociaciones de secciones
              const seccionValues = (edit_secciones || []).map(seccion => [id_horario, seccion]);
              if (seccionValues.length > 0) {
                  db.query('INSERT INTO horario_secciones (id_horario, id_seccion) VALUES ?', [seccionValues], (err) => {
                      if (err) {
                          console.error('Error al agregar nuevas secciones:', err);
                          return res.status(500).send('Error al agregar nuevas secciones');
                      }
                      return res.redirect('/horarios'); // Redirigir a la lista de horarios después de la actualización
                  });
              } else {
                  return res.redirect('/horarios'); // Si no hay secciones, redirigir de todos modos
              }
          });
      });
  });
});

// Eliminar horario
app.get('/horarios/eliminar/:id', function (req, res) {
  var idHorario = req.params.id;

  // Eliminar las relaciones dependientes en la tabla horario_secciones
  var deleteSeccionesQuery = 'DELETE FROM horario_secciones WHERE id_horario = ?';
  db.query(deleteSeccionesQuery, [idHorario], function (error, results) {
      if (error) {
          console.log('Error al eliminar registros en horario_secciones:', error);
          return res.redirect('/horarios'); // Redirigir en caso de error
      }

      // Luego eliminar el horario en la tabla principal
      var deleteHorarioQuery = 'DELETE FROM horarios WHERE id_horario = ?';
      db.query(deleteHorarioQuery, [idHorario], function (error, results) {
          if (error) {
              console.log('Error al eliminar el horario:', error);
              return res.redirect('/horarios'); // Redirigir en caso de error
          }

          console.log('Horario eliminado correctamente:', idHorario);
          return res.redirect('/horarios'); // Redirigir después de eliminar
      });
  });
});

//vista profesor
//modulo calificaciones
//obtener grados y secciones
app.get('/calificaciones', (req, res) => {
  const queryGrados = 'SELECT * FROM grados'; // Consulta para obtener grados
  const querySecciones = 'SELECT * FROM secciones'; // Consulta para obtener secciones
  const queryCursos = 'SELECT * FROM cursos'; // Consulta para obtener cursos

  // Realizar las consultas de grados, secciones y cursos en paralelo
  db.query(queryGrados, (errorGrados, grados) => {
      if (errorGrados) return res.status(500).send(errorGrados);

      db.query(querySecciones, (errorSecciones, secciones) => {
          if (errorSecciones) return res.status(500).send(errorSecciones);

          db.query(queryCursos, (errorCursos, cursos) => {
              if (errorCursos) return res.status(500).send(errorCursos);

              // Renderizar la vista con los grados, secciones y cursos
              res.render('calificaciones/index', { grados, secciones, cursos });
          });
      });
  });
});

//obtener alumnos segun grado y seccion
app.get('/calificaciones/alumnos', (req, res) => {
  const grado = req.query.grado;
  const seccion = req.query.seccion;

  // Añade estas líneas para depuración
  console.log("Grado:", grado); // Debe imprimir "9"
  console.log("Sección:", seccion); // Debe imprimir "B"

  const query = `
      SELECT a.id_alumno, a.nombre, a.apellido, g.nombre_grado, a.seccion,
             IFNULL(c.nombre_curso, 'Sin curso asignado') AS nombre_curso,
             IFNULL(cal.calificacion, 'Sin calificación') AS calificacion
      FROM alumnos a
      JOIN grados g ON a.id_grado = g.id_grado
      LEFT JOIN calificaciones cal ON a.id_alumno = cal.id_alumno
      LEFT JOIN cursos c ON cal.id_curso = c.id_curso
      WHERE a.id_grado = ? AND a.seccion = ?
      GROUP BY a.id_alumno, c.id_curso
      ORDER BY cal.id_calificacion DESC
  `;

  db.query(query, [grado, seccion], (error, results) => {
      if (error) {
          console.error("Error en la consulta:", error);
          return res.status(500).json({ message: "Error en la consulta" });
      }

      console.log("Resultados de la consulta:", results); // Muestra los resultados en la consola
      res.json(results);
  });
});

app.post('/calificaciones/asignar', (req, res) => {
  const { id_alumno, id_curso, bimestre, calificacion } = req.body;

  // Verifica los valores recibidos
  console.log({ id_alumno, id_curso, bimestre, calificacion });

  if (!id_alumno || !id_curso || !bimestre || !calificacion) {
      return res.status(400).json({ message: "Todos los campos son requeridos" });
  }

  const query = `
      INSERT INTO calificaciones (id_alumno, id_curso, bimestre, calificacion)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE calificacion = VALUES(calificacion)
  `;

  db.query(query, [id_alumno, id_curso, bimestre, calificacion], (err, result) => {
      if (err) {
          console.error("Error al asignar la calificación:", err);
          return res.status(500).json({ message: "Error al asignar la calificación" });
      }

      req.session.message = "Calificación asignada con éxito.";
      res.redirect('/calificaciones'); // Redirige a la página de calificaciones
  });
});

app.post('/calificaciones/editar', (req, res) => {
    const { id_alumno, id_curso, calificacion } = req.body;

    const query = `UPDATE calificaciones SET calificacion = ? WHERE id_alumno = ? AND id_curso = ?`;
    db.query(query, [calificacion, id_alumno, id_curso], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Error al editar la calificación." });
        }
        return res.json({ message: "Calificación editada con éxito." });
    });
});

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