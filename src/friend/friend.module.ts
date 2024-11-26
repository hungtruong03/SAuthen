import { Module } from '@nestjs/common';
import { FriendsService } from './friend.service';
import { FriendsController } from './friend.controller';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  controllers: [FriendsController],
  providers: [FriendsService, PrismaService],
})
export class FriendModule {}