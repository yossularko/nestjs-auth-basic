import {
  BadRequestException,
  UnauthorizedException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constant';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(payload: AuthDto) {
    const { email, password } = payload;

    const foundUser = await this.prisma.user.findUnique({ where: { email } });

    if (foundUser) {
      throw new BadRequestException('Email already exist');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return { message: 'signup was successfull' };
  }

  async signin(payload: AuthDto, req: Request, res: Response) {
    const { email, password } = payload;

    const foundUser = await this.prisma.user.findUnique({ where: { email } });

    if (!foundUser) {
      throw new UnauthorizedException('Wrong credentials');
    }

    const isMatch = await this.comparePasswords({
      password,
      hash: foundUser.hashedPassword,
    });

    if (!isMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    const token = await this.signToken({
      id: foundUser.id,
      email: foundUser.email,
    });

    if (!token) {
      throw new ForbiddenException();
    }

    res.cookie('tokenJwt', token);

    return res.send({ message: 'Logged in successfully' });
  }

  async signout(req: Request, res: Response) {
    res.clearCookie('tokenJwt');
    return res.send({ message: 'Logged out successfull' });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    const hashed = await bcrypt.hash(password, saltOrRounds);

    return hashed;
  }

  async comparePasswords(args: { password: string; hash: string }) {
    const isMatch = await bcrypt.compare(args.password, args.hash);
    return isMatch;
  }

  async signToken(args: { id: string; email: string }) {
    const payload = args;

    return await this.jwt.signAsync(payload, { secret: jwtSecret });
  }
}
