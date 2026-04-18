const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const pool = new Pool({
  host: 'localhost',
  user: 'postgres',
  password: 'Nore1403', 
  database: 'softjobs',
  allowExitOnIdle: true
});

const app = express();

// Middlewares base
app.use(cors());
app.use(express.json());

// Requerimiento 2c: Reportar consultas por terminal
app.use((req, res, next) => {
  console.log(`Consulta recibida en: ${req.url}`);
  next();
});

// Requerimiento 2b: Middleware para validar el token en las cabeceras
const validarToken = (req, res, next) => {
  const authorization = req.header("Authorization");
  if (!authorization) return res.status(401).send({ message: "Token no proporcionado" });

  const token = authorization.split("Bearer ")[1];
  try {
    // Requerimiento 3: Verificar validez del token
    jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
    next();
  } catch (error) {
    res.status(401).send({ message: "Token inválido" });
  }
};

// Rutas
app.get("/", (req, res) => {
  res.send("Servidor encendido y conectado");
});

// Requerimiento 1 y 5: Registrar usuario con contraseña encriptada
app.post("/usuarios", async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;
    const salt = bcrypt.genSaltSync(10);
    const passwordEncriptada = bcrypt.hashSync(password, salt);
    
    const consulta = "INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4)";
    const valores = [email, passwordEncriptada, rol, lenguage];
    
    await pool.query(consulta, valores);
    res.status(201).send("Usuario registrado con éxito");
  } catch (error) {
    res.status(500).send({ message: "Error al registrar usuario", error });
  }
});

// Requerimiento 3: Login y generación de token JWT
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const consulta = "SELECT * FROM usuarios WHERE email = $1";
    const { rows: [usuario], rowCount } = await pool.query(consulta, [email]);

    if (rowCount === 0 || !bcrypt.compareSync(password, usuario.password)) {
      return res.status(401).send({ message: "Email o contraseña incorrectos" });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET || 'secret_key');
    res.send({ token });
  } catch (error) {
    res.status(500).send(error);
  }
});

// Requerimiento 1 y 3: Obtener datos del usuario autenticado
app.get("/usuarios", validarToken, async (req, res) => {
  try {
    const authorization = req.header("Authorization");
    const token = authorization.split("Bearer ")[1];
    
    // Decodificar el token para obtener el email
    const { email } = jwt.decode(token);
    
    const consulta = "SELECT * FROM usuarios WHERE email = $1";
    const { rows: [usuario] } = await pool.query(consulta, [email]);
    
    res.send(usuario);
  } catch (error) {
    res.status(500).send({ message: "Error al obtener datos del usuario", error });
  }
});

app.listen(3000, () => console.log("Servidor corriendo en el puerto 3000"));