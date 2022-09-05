import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import * as argon from 'argon2';

import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);

      // save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      // return saved user
      return user;
      // genereate the password has
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials Taken');
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // find the user by email,
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    // if not exist throw exception
    if (!user) {
      throw new ForbiddenException('Credentials Incorrect');
    }

    // compare password
    const pwMatches = await argon.verify(user.hash, dto.password);

    // if password incorrect throw exception
    if (!pwMatches) {
      throw new ForbiddenException('Credentials Incorrect');
    }

    //send back the user
    delete user.hash;
    return user;
  }
}
