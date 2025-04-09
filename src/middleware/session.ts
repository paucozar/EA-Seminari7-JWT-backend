import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../utils/jwt.handle.js";
import { JwtPayload } from "jsonwebtoken";

interface RequestExt extends Request {
    user?: string | JwtPayload;
}

const checkJwt = (req: RequestExt, res: Response, next: NextFunction) => {
    try {
        const jwtByUser = req.headers.authorization || null;
        const jwt = jwtByUser?.split(' ').pop(); // ['Bearer', '11111'] -> ['11111']
        console.log(jwt);
        const isUser = verifyAccessToken(`${jwt}`);
        
        if (!isUser) {
            return res.status(401).send("NO_TIENES_UN_JWT_VALIDO"); // return para evitar llamar a next()
        }
        
        req.user = isUser;
        next(); // Solo si el token es válido, pasa al siguiente middleware
    } catch (e) {
        console.error("Error en checkJwt:", e);
        return res.status(401).send("SESSION_NO_VALID"); // Asegúrate de detener con return
    }
};

const authenticate = (req: RequestExt, res: Response, next: NextFunction) => {
    console.log("Authorization Header:", req.headers.authorization);

    const authHeader = req.headers.authorization;
    if (!authHeader) {
        console.error("Authorization header is missing");
        return res.status(401).json({ message: "Authorization header missing" });
    }

    const token = authHeader.split(" ")[1];
    try {
        const decoded = verifyAccessToken(token);
        console.log("Token decodificado:", decoded);
        req.user = decoded;
        next();
    } catch (error: any) {
        if (error.name === "TokenExpiredError") {
            console.error("Token expirado");
            return res.status(401).json({ message: "Token expired" });
        }
        console.error("Token inválido:", error);
        return res.status(401).json({ message: "Invalid token" });
    }
};

export { checkJwt, authenticate };
