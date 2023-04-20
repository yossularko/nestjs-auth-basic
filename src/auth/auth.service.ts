import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

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

  async signin() {
    return { message: 'signin was successfull' };
  }

  async signout() {
    return { message: 'signout was successfull' };
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    const hashed = await bcrypt.hash(password, saltOrRounds);

    return hashed;
  }
}
