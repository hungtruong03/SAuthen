import { ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { FindAccountDto } from './dto/find-account.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AdminService {
    constructor(private prisma: PrismaService) { }

    async getAccountInfo(findAccountDto: FindAccountDto) {
        const { userId, username } = findAccountDto;

        // Query the database using userId or username
        const account = await this.prisma.account.findFirst({
            where: {
                OR: [{ id: userId }, { username }],
            },
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
            throw new NotFoundException('Account not found');
        }

        return account;
    }

    async removeAccount(findAccountDto: FindAccountDto) {
        const { userId, username } = findAccountDto;

        // Find the account by userId or username
        const account = await this.prisma.account.findFirst({
            where: {
                OR: [{ id: userId }, { username }],
            },
        });

        // Check if account exists
        if (!account) {
            throw new NotFoundException('Account not found');
        }

        // Prevent admin accounts from being deleted
        if (account.role === 'ADMIN') {
            throw new ForbiddenException('Cannot delete admin accounts');
        }

        // Delete the account and any related user or partner data
        if (account.role === 'USER') {
            await this.prisma.user.delete({ where: { accountId: account.id } });
        } else if (account.role === 'PARTNER') {
            await this.prisma.partner.delete({ where: { accountId: account.id } });
        }

        await this.prisma.account.delete({ where: { id: account.id } });

        return { message: 'Account deleted successfully' };
    }

    async updateUserAccount(userId: number, updateData: any) {
        const allowedUserFields = ['firstName', 'lastName', 'avatar', 'email', 'facebook'];
        const allowedAccountFields = ['password'];

        const userData = this.filterFields(updateData, allowedUserFields);
        const accountData = await this.filterAndHashPassword(updateData, allowedAccountFields);

        const user = await this.prisma.user.findUnique({ where: { accountId: userId } });
        if (!user) {
            throw new NotFoundException(`User with ID ${userId} not found`);
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

        return { message: 'User account updated successfully' };
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

        return { message: 'Partner account updated successfully' };
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