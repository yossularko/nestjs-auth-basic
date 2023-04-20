import { Controller, Post, Get, Body, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() payload: AuthDto) {
    return this.authService.signup(payload);
  }

  @Post('signin')
  signin(@Body() payload: AuthDto, @Req() req: Request, @Res() res: Response) {
    return this.authService.signin(payload, req, res);
  }

  @Get('signout')
  signout(@Req() req: Request, @Res() res: Response) {
    return this.authService.signout(req, res);
  }
}
