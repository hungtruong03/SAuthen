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
import * as nodemailer from 'nodemailer';
import { FindAccountDto } from '../admin/dto/find-account.dto';
import { WebSocket } from 'ws';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        @InjectRedis() private readonly redisClient: Redis,
    ) { }

    private notificationSocket: WebSocket | null = null;

    async requestOtp(email: string) {
        const existingEmail = await this.prisma.user.findUnique({
            where: { email },
        });

        if (existingEmail) {
            throw new ConflictException('Email is already registered');
        }

        const otpKey = `otp:${email}`;
        const cooldownKey = `otpCooldown:${email}`;

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

        // Send OTP via Email
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSKEY,
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'VouApp OTP Code',
            text: `Your VouApp OTP code is: ${otp}. This code is valid for 5 minutes.`,
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log(`OTP ${otp} sent to ${email}`);
        } catch (error) {
            console.error('Error sending OTP via email:', error);
            throw new BadRequestException('Failed to send OTP. Please try again later.');
        }

        return { message: 'OTP sent successfully' };
    }

    async verifyOtp(email: string, otp: string): Promise<boolean> {
        const otpKey = `otp:${email}`;
        const storedOtp = await this.redisClient.get(otpKey);

        if (!storedOtp || storedOtp !== otp) {
            return false;
        }

        return true;
    }

    async deleteOtp(email: string, otp: string): Promise<void> {
        const otpKey = `otp:${email}`;
        const storedOtp = await this.redisClient.get(otpKey);

        if (!storedOtp || storedOtp !== otp) {
            return;
        }

        // Delete OTP after verification
        await this.redisClient.del(otpKey);
    }

    async register(dto: RegisterDto) {
        const { username, password, firstName, lastName, email, phone, otp } = dto;

        const isOtpValid = await this.verifyOtp(email, otp);
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
        await this.verifyOtp(email, otp);

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

        if (account.disabled === true) {
            throw new ForbiddenException('Your account is disabled. Please contact support.');
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
        try {
            if (this.notificationSocket) {
                this.notificationSocket.close();
            }

            const notificationUrl = process.env.URL_SERVICE || 'ws://notification:3005';
            console.log(notificationUrl);
            this.notificationSocket = new WebSocket(`${notificationUrl}?token=${accessToken}`);
            // console.log(this.notificationSocket);
            
            this.notificationSocket.on('open', () => {
                console.log(`🔗 User ${account.id} connected to Notification Service`);
            });

            this.notificationSocket.on('message', (message) => {
                const jsonString = Buffer.isBuffer(message)
                    ? Buffer.from(message).toString('utf8')
                    : message;

                const parsedData = JSON.parse(jsonString);
                console.log(`📩 Notification received for User ${account.id}:`, parsedData);
            });

            this.notificationSocket.on('close', () => {
                console.log(`❌ WebSocket for User ${account.id} disconnected`);
            });

            this.notificationSocket.on('error', (error) => {
                console.error(`⚠️ WebSocket error for User ${account.id}:`, error);
            });
        } catch (err) {
            console.error('Error setting up WebSocket:', err);
        }

        return response;
    }

    async refreshAccessToken(userId: string, refreshToken: string) {
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

    async profile(userId: string, role: Role) {
        // Query the database
        const account = await this.prisma.account.findFirst({
            where: { id: userId },
            select: {
                id: true,
                username: true,
                refreshToken: true,
                createdDate: true,
                role: true,
                disabled: true,
                user: role === 'USER' ? true : false,
                partner: role === 'PARTNER' ? true : false,
            },
        });

        if (!account) {
            throw new NotFoundException('Account not found');
        }

        return account;
    }

    async updateUserAccount(userId: string, updateData: any) {
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

    async updatePartnerAccount(partnerId: string, updateData: any) {
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

    private generateAccessToken(userId: string, role: Role): string {
        const ISS = this.getISS(role);
        return this.jwtService.sign({ userId, role, iss: ISS }, { expiresIn: '1d' });
    }

    private getISS(role: Role): string {
        if (role === 'ADMIN') {
            return 'JWT_SECRET_ADMIN';
        } else if (role === 'PARTNER') {
            return 'JWT_SECRET_PARTNER';
        }
        return 'JWT_SECRET';
    }

    private generateRefreshToken(userId: string): string {
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

    async createAdmin(username: string) {
        const existingAccount = await this.prisma.account.findUnique({
            where: { username },
        });

        if (existingAccount) {
            throw new ConflictException('Username is already taken');
        }

        const hashedPassword = await bcrypt.hash('123456', 10);

        return await this.prisma.account.create({
            data: {
                username,
                password: hashedPassword,
                role: 'ADMIN',
            },
        });
    }

    async checkExist(findAccountDto: FindAccountDto) {
        const { userId, username } = findAccountDto;

        // Query the database
        const account = await this.prisma.account.findFirst({
            where: userId ? { id: userId } : { username },
            select: {
                id: true,
                username: true,
                refreshToken: true,
                createdDate: true,
                role: true,
                user: true,
                partner: true,
            },
        });

        if (!account) {
            return { exist: false };
        }

        return { exist: true };
    }

    async getAccountByPhone(phoneNumber: string) {
        const user = await this.prisma.user.findFirst({
            where: { phone: phoneNumber },
            select: {
                firstName: true,
                lastName: true,
                phone: true,
                email: true,
                facebook: true,
                avatar: true,
                account: true,
            },
        });

        if (!user) {
            throw new NotFoundException('User not found');
        }

        return user;
    }

    async getAccountsByRoles(roles: Role[]) {
        try {
            const accounts = await this.prisma.account.findMany({
                where: {
                    role: { in: roles },
                },
                select: {
                    id: true,
                    username: true,
                    createdDate: true,
                    disabled: true,
                    user: true,
                    partner: true,
                },
            });

            return accounts;
        } catch (error) {
            console.error('Error fetching accounts:', error);
            throw new BadRequestException('Error fetching accounts');
        }
    }

    async getAllAccounts() {
        try {
            const accounts = await this.prisma.account.findMany({
                select: {
                    id: true,
                    username: true,
                    createdDate: true,
                    disabled: true,
                    role: true,
                    user: true,
                    partner: true,
                },
            });

            return accounts;
        } catch (error) {
            throw new BadRequestException('Error fetching accounts');
        }
    }

    async getNewlyRegisteredAccounts(role: Role, days: number) {
        const result = [];

        for (let i = 0; i < days; i++) {
            const date = new Date();
            date.setDate(date.getDate() - i);

            const count = await this.prisma.account.count({
                where: {
                    role: role,
                    createdDate: {
                        gte: new Date(date.setHours(0, 0, 0, 0)),
                        lt: new Date(date.setHours(23, 59, 59, 999)),
                    },
                },
            });

            result.push({
                date: date.toISOString().split('T')[0],
                count: count,
            });
        }

        return result.reverse();
    }
}