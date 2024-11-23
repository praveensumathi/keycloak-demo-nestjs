
import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(private jwtService: JwtService) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        if (!token) {
            throw new UnauthorizedException();
        }
        try {
            const payload = await this.jwtService.verifyAsync(
                token,
                {
                    algorithms: ["RS256"],
                    issuer: "http://localhost:8080/realms/freelancer",
                    publicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqmKJSBX/QfDBpVeaHakBlwckMo4/LKVoP8WHRxnHJnUTp9daBkX1EuMMFMOGzKCeDI4n0Ez3mWxd5mZD1GPnNX4l1Dt0TfwDda+4dcnmmhbJ2fzGT+PCfRipYIZdCVWuUIpnwLoCYd0jZp4m68CmqEUs/voLplQxuWYXwCw55h3F70BS/m6W2OyY7Cq6xseZ4byrqr09fN44W9rEsCthp6p8Bn0uG5unDxZjqeQANnXLtOL0ZLNicb2S9gRE7OpVNVW+EkAC0wzD7rth0Niw0bbvEdqzKhtlXez2e2c2OvpDmcWQnYul8uyuW1iLhpe7UBxQji9KvriSb3mV0qR4aQIDAQAB\n-----END PUBLIC KEY-----"
                }
            );
            request['email'] = payload.email;
        } catch {
            throw new UnauthorizedException();
        }
        return true;
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
