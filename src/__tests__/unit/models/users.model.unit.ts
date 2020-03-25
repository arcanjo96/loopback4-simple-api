import {expect} from '@loopback/testlab';

describe('Users (unit)', () => {
  describe('Retornar um usuário', () => {
    it('Irá retornar o email do user', () => {
      const user = {
        id: "1",
        email: "teste@teste.com",
        password: "testando"
      };

      const {email} = user;
      expect(email).to.equal('teste@teste.com');
    });
  });
});
