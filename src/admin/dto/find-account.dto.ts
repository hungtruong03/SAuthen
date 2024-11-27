import { IsInt, IsString, ValidateIf } from 'class-validator';

export class FindAccountDto {
  @ValidateIf((o) => !o.username) // Require userId if username is not provided
  @IsInt()
  userId?: number;

  @ValidateIf((o) => !o.userId) // Require username if userId is not provided
  @IsString()
  username?: string;
}