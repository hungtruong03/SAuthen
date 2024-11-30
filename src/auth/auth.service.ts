import { Injectable, ConflictException, UnauthorizedException, BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { Role } from '@prisma/client';
import { PartnerRegisterDto } from './dto/partner-register.dto';
import { InjectRedis } from '@nestjs-modules/ioredis';
import { Redis } from 'ioredis';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwtService: JwtService, @InjectRedis() private readonly redisClient: Redis,) { }

    async requestOtp(phone: string) {
        const existingPhone = await this.prisma.user.findUnique({
            where: { phone },
        });

        if (existingPhone) {
            throw new ConflictException('Phone number is already registered');
        }

        const otpKey = `otp:${phone}`;
        const cooldownKey = `otpCooldown:${phone}`;

        // Check cooldown
        const cooldown = await this.redisClient.get(cooldownKey);
        if (cooldown) {
            throw new BadRequestException(
                'Please wait before requesting another OTP',
            );
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Store OTP
        await this.redisClient.set(otpKey, otp, 'EX', 300);

        // Set cooldown
        await this.redisClient.set(cooldownKey, '1', 'EX', 30);

        // Simulate sending OTP
        console.log(`Sending OTP ${otp} to ${phone}`);

        return { message: 'OTP sent successfully' };
    }

    async verifyOtp(phone: string, otp: string): Promise<boolean> {
        const otpKey = `otp:${phone}`;
        const storedOtp = await this.redisClient.get(otpKey);

        if (!storedOtp || storedOtp !== otp) {
            return false;
        }

        return true;
    }

    async deleteOtp(phone: string, otp: string): Promise<void> {
        const otpKey = `otp:${phone}`;
        const storedOtp = await this.redisClient.get(otpKey);

        if (!storedOtp || storedOtp !== otp) {
            return;
        }

        // Delete OTP after verification
        await this.redisClient.del(otpKey);
    }

    async register(dto: RegisterDto) {
        const { username, password, firstName, lastName, email, phone, otp } = dto;

        const isOtpValid = await this.verifyOtp(phone, otp);
        if (!isOtpValid) {
            throw new BadRequestException('Invalid or expired OTP');
        }

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
                role: 'USER',
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

        // Delete the OTP after successful registration
        await this.verifyOtp(phone, otp);

        // Return the response
        return {
            accountId: account.id,
            username: account.username,
            role: account.role,
            userId: user.id,
        };
    }

    async registerPartner(partnerRegisterDto: PartnerRegisterDto) {
        const {
            username,
            password,
            companyName,
            avatar,
            field,
            address,
            gpsLat,
            gpsLong,
        } = partnerRegisterDto;

        // Check if the username is already taken
        const existingAccount = await this.prisma.account.findUnique({ where: { username } });
        if (existingAccount) {
            throw new ConflictException('Username is already taken');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create account and partner
        const account = await this.prisma.account.create({
            data: {
                username,
                password: hashedPassword,
                role: 'PARTNER',
                partner: {
                    create: {
                        companyName,
                        avatar,
                        field,
                        address,
                        gpsLat,
                        gpsLong,
                        status: 'Unverified',
                    },
                },
            },
        });

        return {
            message: 'Partner registered successfully',
            accountId: account.id,
        };
    }

    async login(dto: LoginDto) {
        const { username, password } = dto;

        const account = await this.prisma.account.findUnique({
            where: { username },
            include: { partner: true }, // Include partner data to check status
        });

        if (!account) {
            throw new UnauthorizedException('Invalid username');
        }

        const isPasswordValid = await bcrypt.compare(password, account.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password');
        }

        // Check if the account is a partner and is unverified
        if (account.role === 'PARTNER' && account.partner?.status === 'Unverified') {
            throw new ForbiddenException('Your account is not verified yet. Please contact support.');
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