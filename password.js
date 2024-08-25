const bcrypt = require('bcrypt');
const saltRounds = 10; // Número de rondas de sal

// Función para encriptar una contraseña
const hashPassword = async (plainPassword) => {
  try {
    const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
    return hashedPassword;
  } catch (error) {
    console.error('Error al encriptar la contraseña:', error);
    throw error;
  }
};

// Ejemplo de uso para encriptar "123456"
const createHashedPassword = async () => {
  const plainPassword = '123456';
  try {
    const hashedPassword = await hashPassword(plainPassword);
    console.log('Contraseña encriptada:', hashedPassword);
  } catch (error) {
    console.error('Error al encriptar la contraseña:', error);
  }
};

createHashedPassword();