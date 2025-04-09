import pkg from "jsonwebtoken";
import jwt from "jsonwebtoken"; //Importamos la librería jsonwebtoken para crear y verificar tokens JWT

const ACCESS_TOKEN_SECRET = 'access_token_secret'; //Clave secreta para firmar el token de acceso
const REFRESH_TOKEN_SECRET = 'refresh_token_secret'; //Clave secreta para firmar el token de refresco
const ACCESS_TOKEN_EXPIRES_IN = '15m'; //Tiempo de expiración del token de acceso
const REFRESH_TOKEN_EXPIRES_IN = '7d'; //Tiempo de expiración del token de refresco

//No debemos pasar información sensible en el payload, en este caso vamos a pasar como parametro el ID del usuario
const generateTokens = (userId:string, role: string) => {
    const accessToken = jwt.sign({id: userId, role: role}, ACCESS_TOKEN_SECRET, {expiresIn: ACCESS_TOKEN_EXPIRES_IN});

    const refreshToken = jwt.sign({id: userId, role: role}, REFRESH_TOKEN_SECRET, {expiresIn: REFRESH_TOKEN_EXPIRES_IN});
    
    return {accessToken, refreshToken};
};

const verifyAccessToken = (token: string) => {
    return jwt.verify(token, ACCESS_TOKEN_SECRET);
};

const verifyRefreshToken = (token: string) => {
    return jwt.verify(token, REFRESH_TOKEN_SECRET);
}

export { generateTokens, verifyAccessToken, verifyRefreshToken };