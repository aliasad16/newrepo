const fs = require('fs');
const bcrypt = require('bcryptjs');

const userCount = 100; // Change this to the number of users you want
const users = [];

for (let i = 1; i <= userCount; i++) {
    const username = `user${i}`;
    const email = `user${i}@example.com`;
    const password = `password${i}`; // Use simple passwords for testing
    const hashedPassword = bcrypt.hashSync(password, 10); // Hash the password

    users.push({
        username: username,
        email: email,
        password: hashedPassword,
    });
}

// Write users to users.json
fs.writeFileSync('./users.json', JSON.stringify(users, null, 2));

console.log(`${userCount} users generated and saved to users.json.`);
