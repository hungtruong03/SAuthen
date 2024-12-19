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

        // Fetch the account and include related user or partner data
        const account = await this.prisma.account.findUnique({
            where: { username },
            include: {
                user: true,    // Include user data for USER role
                partner: true, // Include partner data for PARTNER role
            },
        });

        if (!account) {
            throw new UnauthorizedException('Invalid username');
        }

        // Verify the password
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

        // Construct the response
        const response: any = {
            userId: account.id,
            accessToken,
            refreshToken,
            role: account.role,
            account: {
                username: account.username,
                createdDate: account.createdDate,
            },
        };

        // Include role-specific data
        if (account.role === 'USER' && account.user) {
            response.user = {
                firstName: account.user.firstName,
                lastName: account.user.lastName,
                phone: account.user.phone,
                email: account.user.email,
                avatar: account.user.avatar,
            };
        } else if (account.role === 'PARTNER' && account.partner) {
            response.partner = {
                companyName: account.partner.companyName,
                avatar: account.partner.avatar,
                field: account.partner.field,
                address: account.partner.address,
                gpsLat: account.partner.gpsLat,
                gpsLong: account.partner.gpsLong,
                status: account.partner.status,
            };
        }

        return response;
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

    async profile(userId: number, role: Role) {
        // Query the database
        const account = await this.prisma.account.findFirst({
            where: { id: userId },
            select: {
                id: true,
                username: true,
                refreshToken: true,
                createdDate: true,
                role: true,
                user: role === 'USER' ? true : false,
                partner: role === 'PARTNER' ? true : false,
            },
        });

        if (!account) {
            throw new NotFoundException('Account not found');
        }

        return account;
    }

    async updateUserAccount(userId: number, updateData: any) {
        const allowedUserFields = ['firstName', 'lastName', 'avatar', 'email', 'facebook'];
        const allowedAccountFields = ['password'];

        const userData: { email?: string } = this.filterFields(updateData, allowedUserFields);
        const accountData = await this.filterAndHashPassword(updateData, allowedAccountFields);

        const user = await this.prisma.user.findUnique({ where: { accountId: userId } });
        if (!user) {
            throw new NotFoundException(`User with ID ${userId} not found`);
        }

        // Check if the email is unique (if provided)
        if (userData.email) {
            const existingUser = await this.prisma.user.findUnique({ where: { email: userData.email } });
            if (existingUser && existingUser.accountId !== userId) {
                throw new ConflictException(`Email ${userData.email} is already in use`);
            }
        }

        // Update User table fields
        if (Object.keys(userData).length > 0) {
            await this.prisma.user.update({
                where: { accountId: userId },
                data: userData,
            });
        }

        // Update Account table fields
        if (Object.keys(accountData).length > 0) {
            await this.prisma.account.update({
                where: { id: user.accountId },
                data: accountData,
            });
        }

        return { message: 'Account updated successfully' };
    }

    async updatePartnerAccount(partnerId: number, updateData: any) {
        const allowedPartnerFields = ['companyName', 'avatar', 'field', 'address', 'gpsLat', 'gpsLong', 'status'];
        const allowedAccountFields = ['password'];

        const partnerData = this.filterFields(updateData, allowedPartnerFields);
        const accountData = await this.filterAndHashPassword(updateData, allowedAccountFields);

        const partner = await this.prisma.partner.findUnique({ where: { accountId: partnerId } });
        if (!partner) {
            throw new NotFoundException(`Partner with ID ${partnerId} not found`);
        }

        // Update Partner table fields
        if (Object.keys(partnerData).length > 0) {
            await this.prisma.partner.update({
                where: { accountId: partnerId },
                data: partnerData,
            });
        }

        // Update Account table fields
        if (Object.keys(accountData).length > 0) {
            await this.prisma.account.update({
                where: { id: partner.accountId },
                data: accountData,
            });
        }

        return { message: 'Account updated successfully' };
    }

    private generateAccessToken(userId: number, role: Role): string {
        return this.jwtService.sign({ userId, role });
    }

    private generateRefreshToken(userId: number): string {
        return this.jwtService.sign({ userId }, { expiresIn: '7d' });
    }

    private filterFields(updateData: any, allowedFields: string[]) {
        const filteredData = {};
        for (const key of allowedFields) {
            if (updateData[key] !== undefined) {
                filteredData[key] = updateData[key];
            }
        }
        return filteredData;
    }

    private async filterAndHashPassword(updateData: any, allowedFields: string[]) {
        // Define filteredData with an explicit type
        const filteredData: { [key: string]: any; password?: string } = {};

        // Filter the allowed fields
        for (const key of allowedFields) {
            if (updateData[key] !== undefined) {
                filteredData[key] = updateData[key];
            }
        }

        // If password exists, hash it
        if (filteredData.password) {
            const salt = await bcrypt.genSalt();
            filteredData.password = await bcrypt.hash(filteredData.password, salt);
        }

        return filteredData;
    }
}