import { Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import { User } from 'src/user/entities/user.entity';
import { UserPayload } from './models/UserPayload';

import { JwtService } from '@nestjs/jwt';
import { UserToken } from './models/UserToken';

@Injectable()
export class AuthService {
  constructor(
    private readonly useService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  login(user: User): UserToken {
    // Transforma o user em um JWT
    const payload: UserPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };

    const jwtToken = this.jwtService.sign(payload);

    return {
      access_token: jwtToken,
    };
  }

  async validateUser(email: string, password: string) {
    const user = await this.useService.findByEmail(email);

    if (user) {
      //Checar se a senha informada corresponde a hash do banco

      const isPassWordValid = await bcrypt.compare(password, user.password);

      if (isPassWordValid) {
        return {
          ...user,
          password: undefined,
        };
      }
    }
    //Se chegar aqui, significa que não encontrou um user e / ou a senha não corresponde
    throw new Error('Email addres or password provieded is incorrect');
  }
}
