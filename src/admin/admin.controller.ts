import { Body, Controller, Post, Delete, Request, UnauthorizedException, Param, ParseIntPipe } from '@nestjs/common';
import { AdminService } from './admin.service';
import { FindAccountDto } from './dto/find-account.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UpdatePartnerDto } from './dto/update-partner.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { CreatePartnerDto } from './dto/create-partner.dto';

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) { }

  @Post('getAccount')
  async getAccountInfo(@Request() req, @Body() findAccountDto: FindAccountDto) {
    if (req.role !== 'ADMIN') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    return this.adminService.getAccountInfo(findAccountDto);
  }

  @Delete('removeAccount')
  async removeAccount(@Request() req, @Body() findAccountDto: FindAccountDto) {
    if (req.role !== 'ADMIN') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    return this.adminService.removeAccount(findAccountDto);
  }

  @Post('create/user')
  async createUserAccount(@Request() req, @Body() createUserAccountDto: CreateUserDto,) {
    if (req.role !== 'ADMIN') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    return this.adminService.createUserAccount(createUserAccountDto);
  }

  @Post('create/partner')
  async createPartnerAccount(@Request() req, @Body() createPartnerAccountDto: CreatePartnerDto) {
    if (req.role !== 'ADMIN') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    return this.adminService.createPartnerAccount(createPartnerAccountDto);
  }

  @Post('update/user/:userId')
  async updateUserAccount(@Request() req, @Param('userId', ParseIntPipe) userId: number, @Body() updateData: UpdateUserDto) {
    if (req.role !== 'ADMIN') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    if (!userId) {
      throw new Error('UserId is required');
    }

    return this.adminService.updateUserAccount(userId, updateData);
  }

  @Post('update/partner/:partnerId')
  async updatePartnerAccount(@Request() req, @Param('partnerId', ParseIntPipe) partnerId: number, @Body() updateData: UpdatePartnerDto) {
    if (req.role !== 'ADMIN') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    if (!partnerId) {
      throw new Error('PartnerId is required');
    }

    return this.adminService.updatePartnerAccount(partnerId, updateData);
  }
}