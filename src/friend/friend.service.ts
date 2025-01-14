import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class FriendsService {
  constructor(private prisma: PrismaService) { }

  async addFriend(userId: string, friendId: string) {
    if (userId === friendId) {
      throw new ConflictException('You cannot add yourself as a friend');
    }

    const [user, friend] = await Promise.all([
      this.prisma.user.findUnique({ where: { accountId: userId } }),
      this.prisma.user.findUnique({ where: { accountId: friendId } }),
    ]);

    if (!user || !friend) {
      throw new NotFoundException('User or Friend not found');
    }

    const existingFriendship = await this.prisma.user.findFirst({
      where: {
        accountId: userId,
        friends: { some: { accountId: friendId } },
      },
    });

    if (existingFriendship) {
      throw new ConflictException('You are already friends');
    }

    await this.prisma.user.update({
      where: { accountId: userId },
      data: {
        friends: { connect: { accountId: friendId } },
      },
    });

    await this.prisma.user.update({
      where: { accountId: friendId },
      data: {
        friends: { connect: { accountId: userId } },
      },
    });

    return { message: 'Friend added successfully' };
  }

  async removeFriend(userId: string, friendId: string) {
    const [user, friend] = await Promise.all([
      this.prisma.user.findUnique({ where: { accountId: userId } }),
      this.prisma.user.findUnique({ where: { accountId: friendId } }),
    ]);

    if (!user || !friend) {
      throw new NotFoundException('User or Friend not found');
    }

    const existingFriendship = await this.prisma.user.findFirst({
      where: {
        accountId: userId,
        friends: { some: { accountId: friendId } },
      },
    });

    if (!existingFriendship) {
      throw new NotFoundException('Friendship not found');
    }

    await this.prisma.user.update({
      where: { accountId: userId },
      data: {
        friends: { disconnect: { accountId: friendId } },
      },
    });

    await this.prisma.user.update({
      where: { accountId: friendId },
      data: {
        friends: { disconnect: { accountId: userId } },
      },
    });

    return { message: 'Friend removed successfully' };
  }

  async listFriends(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { accountId: userId },
      include: { friends: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user.friends;
  }
}
