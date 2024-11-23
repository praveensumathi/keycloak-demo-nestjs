import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { AuthGuard } from './auth/auth.guard';

@Controller()
export class AppController {

  @UseGuards(AuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    return req.email;
  }
}
