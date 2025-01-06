import { BadRequestException, Body, Controller, Get, Post, Request, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { PartnerRegisterDto } from './dto/partner-register.dto';
import { UpdateUserDto } from 'src/admin/dto/update-user.dto';
import { UpdatePartnerDto } from 'src/admin/dto/update-partner.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('requestotp')
    async requestOtp(@Body('email') email: string) {
        if (!email) {
            throw new BadRequestException('Email is required');
        }
        return this.authService.requestOtp(email);
    }

    @Post('register')
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @Post('register/partner')
    async registerPartner(@Body() partnerRegisterDto: PartnerRegisterDto) {
        return this.authService.registerPartner(partnerRegisterDto);
    }

    @Post('login')
    async login(@Body() loginDto: LoginDto) {
        return this.authService.login(loginDto);
    }

    @Post('refreshAccessToken')
    async refreshToken(@Body() refreshTokenDto: { userId: number, refreshToken: string }) {
        const { userId, refreshToken } = refreshTokenDto;
        return this.authService.refreshAccessToken(userId, refreshToken);
    }

    @Get('profile')
    async getAccountInfo(@Request() req) {
        if (!req.role) {
            throw new Error('Invalid role');
        }

        return this.authService.profile(req.userId, req.role);
    }

    @Post('update/user')
    async updateUserAccount(@Request() req, @Body() updateData: UpdateUserDto) {
        if (req.role !== 'USER') {
            throw new UnauthorizedException('You are not authorized to access this resource');
        }

        if (!req.userId) {
            throw new Error('userId is missing');
        }

        return this.authService.updateUserAccount(req.userId, updateData);
    }

    @Post('update/partner')
    async updatePartnerAccount(@Request() req, @Body() updateData: UpdatePartnerDto) {
        if (req.role !== 'PARTNER') {
            throw new UnauthorizedException('You are not authorized to access this resource');
        }

        if (!req.userId) {
            throw new Error('userId is missing');
        }

        return this.authService.updatePartnerAccount(req.userId, updateData);
    }
}