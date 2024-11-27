import { IsString, IsOptional, IsNotEmpty, IsNumber, IsEnum } from 'class-validator';
import { Status } from '@prisma/client';

export class CreatePartnerDto {
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

  @IsEnum(Status)
  @IsOptional()
  status?: Status = Status.Unverified;
}