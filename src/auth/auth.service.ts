import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { Role } from '@prisma/client';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwtService: JwtService,) { }

    async register(dto: RegisterDto) {
        const { username, password, role, firstName, lastName, email, phone } = dto;

        // Check if username already exists
        const existingAccount = await this.prisma.account.findUnique({
            where: { username },
        });

        if (existingAccount) {
            throw new ConflictException('Username is already taken');
        }

        // Check if phone number already exists
        const existingPhone = await this.prisma.user.findUnique({
            where: { phone },
        });

        if (existingPhone) {
            throw new ConflictException('Phone number is already taken');
        }

        // Check if email already exists
        const existingEmail = await this.prisma.user.findUnique({
            where: { email },
        });

        if (existingEmail) {
            throw new ConflictException('Email is already taken');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the account
        const account = await this.prisma.account.create({
            data: {
                username,
                password: hashedPassword,
                role,
            },
        });

        // Create the user
        const user = await this.prisma.user.create({
            data: {
                accountId: account.id,
                firstName,
                lastName,
                email,
                phone,
            },
        });

        // Return the response
        return {
            accountId: account.id,
            username: account.username,
            role: account.role,
            userId: user.id,
        };
    }

    async login(dto: LoginDto) {
        const { username, password } = dto;

        const account = await this.prisma.account.findUnique({ where: { username } });
        if (!account) {
            throw new UnauthorizedException('Invalid username');
        }

        const isPasswordValid = await bcrypt.compare(password, account.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password');
        }

        // Generate Access Token and Refresh Token
        const accessToken = this.generateAccessToken(account.id, account.role);
        const refreshToken = this.generateRefreshToken(account.id);

        // Save the Refresh Token in the database
        await this.prisma.account.update({
            where: { id: account.id },
            data: { refreshToken },
        });

        return { userId: account.id, accessToken, refreshToken };
    }

    async refreshAccessToken(userId: number, refreshToken: string) {
        // Validate the Refresh Token
        const account = await this.prisma.account.findUnique({ where: { id: userId } });
        if (!account || account.refreshToken !== refreshToken) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        try {
            // Verify the Refresh Token
            this.jwtService.verify(refreshToken);

            // Generate a new Access Token
            const newAccessToken = this.generateAccessToken(userId, account.role);

            return { accessToken: newAccessToken };
        } catch (error) {
            throw new UnauthorizedException('Invalid or expired refresh token');
        }
    }

    private generateAccessToken(userId: number, role: Role): string {
        return this.jwtService.sign({ userId, role });
    }

    private generateRefreshToken(userId: number): string {
        return this.jwtService.sign({ userId }, { expiresIn: '7d' });
    }
}