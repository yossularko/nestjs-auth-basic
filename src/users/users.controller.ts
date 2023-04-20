import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { JwtAuthGuard } from 'src/auth/jwt.guard';
import { UsersService } from './users.service';

@UseGuards(JwtAuthGuard)
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('/:id')
  getMyUser(@Param('id') id: string, @Req() req: Request) {
    return this.usersService.getMyUser(id, req);
  }

  @Get()
  getUsers() {
    return this.usersService.getUsers();
  }
}
