const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient(); // instantiating the prisma client

// start using built-in Prisma Client methods
// syntax : clientInstance.tableName.method() - CRUD operations

async function main() {
  const newUser = await prisma.user.create({
    data: {
      username: "test user",
      password: "testpassword",
    },
  });

  console.log(newUser);
}
main()
  .catch((e) => console.error(e))
  .finally(async () => {
    await prisma.$disconnect();
  });
