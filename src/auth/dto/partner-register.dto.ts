import { IsString, IsNotEmpty, IsNumber, IsOptional } from 'class-validator';

export class PartnerRegisterDto {
    @IsString()
    @IsNotEmpty()
    username: string;

    @IsString()
    @IsNotEmpty()
    password: string;

    @IsString()
    @IsNotEmpty()
    companyName: string;

    @IsString()
    @IsOptional()
    avatar?: string;

    @IsString()
    @IsNotEmpty()
    field: string;

    @IsString()
    @IsNotEmpty()
    address: string;

    @IsNumber()
    @IsNotEmpty()
    gpsLat: number;

    @IsNumber()
    @IsNotEmpty()
    gpsLong: number;
}