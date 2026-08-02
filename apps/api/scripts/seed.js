"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const bcryptjs_1 = require("bcryptjs");
const dotenv_1 = require("dotenv");
const node_path_1 = require("node:path");
(0, dotenv_1.config)({
    path: (0, node_path_1.resolve)(process.cwd(), '../../.env'),
});
const prisma = new client_1.PrismaClient();
function getRequiredEnvironmentVariable(name) {
    const value = process.env[name]?.trim();
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}
async function seedRoles() {
    await prisma.role.upsert({
        where: {
            code: client_1.RoleCode.ADMIN,
        },
        update: {
            name: 'Administrator',
            description: 'Full administrative access to CYRP Platform',
        },
        create: {
            code: client_1.RoleCode.ADMIN,
            name: 'Administrator',
            description: 'Full administrative access to CYRP Platform',
        },
    });
    await prisma.role.upsert({
        where: {
            code: client_1.RoleCode.USER,
        },
        update: {
            name: 'User',
            description: 'Standard CYRP Platform user',
        },
        create: {
            code: client_1.RoleCode.USER,
            name: 'User',
            description: 'Standard CYRP Platform user',
        },
    });
}
async function seedAdministrator() {
    const email = getRequiredEnvironmentVariable('SEED_ADMIN_EMAIL').toLowerCase();
    const password = getRequiredEnvironmentVariable('SEED_ADMIN_PASSWORD');
    const fullName = process.env.SEED_ADMIN_NAME?.trim() ||
        'System Administrator';
    if (password.length < 12) {
        throw new Error('SEED_ADMIN_PASSWORD must contain at least 12 characters');
    }
    const adminRole = await prisma.role.findUniqueOrThrow({
        where: {
            code: client_1.RoleCode.ADMIN,
        },
    });
    const existingAdministrator = await prisma.user.findUnique({
        where: {
            email,
        },
    });
    if (existingAdministrator) {
        await prisma.user.update({
            where: {
                id: existingAdministrator.id,
            },
            data: {
                fullName,
                status: client_1.UserStatus.ACTIVE,
                roleId: adminRole.id,
            },
        });
        console.log(`Administrator already exists: ${email}`);
        return;
    }
    const passwordHash = await (0, bcryptjs_1.hash)(password, 12);
    await prisma.user.create({
        data: {
            email,
            fullName,
            passwordHash,
            status: client_1.UserStatus.ACTIVE,
            roleId: adminRole.id,
        },
    });
    console.log(`Administrator created: ${email}`);
}
async function main() {
    if (process.env.NODE_ENV === 'production') {
        throw new Error('Development seed must not run in production');
    }
    await seedRoles();
    await seedAdministrator();
    console.log('CYRP identity seed completed');
}
main()
    .catch((error) => {
    console.error('CYRP identity seed failed');
    if (error instanceof Error) {
        console.error(error.message);
    }
    else {
        console.error(error);
    }
    process.exitCode = 1;
})
    .finally(async () => {
    await prisma.$disconnect();
});
