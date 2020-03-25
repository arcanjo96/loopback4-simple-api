import {repository} from '@loopback/repository';
import {HttpErrors, post, requestBody} from '@loopback/rest';
import {promisify} from 'util';
import {Users} from '../models';
import {Credentials, JWT_SECRET} from '../providers/auth';
import {UsersRepository} from '../repositories';

const {sign} = require('jsonwebtoken');
const signAsync = promisify(sign);

export class UsersController {
  constructor(
    @repository(UsersRepository) private userRepository: UsersRepository,
  ) {}

  @post('/users')
  async createUser(@requestBody() user: Users): Promise<Users> {
    return await this.userRepository.create(user);
  }

  @post('/users/login')
  async login(@requestBody() credentials: Credentials) {
    if (!credentials.email || !credentials.password) throw new HttpErrors.BadRequest('Missing Username or Password');
    const user = await this.userRepository.findOne({where: {email: credentials.email}});
    if (!user) throw new HttpErrors.Unauthorized('Invalid credentials');

    const isPasswordMatched = user.password === credentials.password;
    if (!isPasswordMatched) throw new HttpErrors.Unauthorized('Invalid credentials');

    const tokenObject = {username: credentials.email};
    const token = await signAsync(tokenObject, JWT_SECRET);

    return {
      token,
    };
  }
}
