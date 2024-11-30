import { BadRequestException, Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { PartnerRegisterDto } from './dto/partner-register.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('requestotp')
    async requestOtp(@Body('phone') phone: string) {
        if (!phone) {
            throw new BadRequestException('Phone number is required');
        }
        return this.authService.requestOtp(phone);
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
}