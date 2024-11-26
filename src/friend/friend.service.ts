import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class FriendsService {
  constructor(private prisma: PrismaService) { }

  // Add a friend
  async addFriend(userId: number, friendId: number) {
    if (userId === friendId) {
      throw new ConflictException('You cannot add yourself as a friend');
    }

    // Check if both users exist
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    const friend = await this.prisma.user.findUnique({ where: { id: friendId } });

    if (!user || !friend) {
      throw new NotFoundException('User or Friend not found');
    }

    // Check if they are already friends
    const existingFriendship = await this.prisma.user.findFirst({
      where: {
        AND: [
          { id: userId },
          { friends: { some: { id: friendId } } },
        ],
      },
    });

    if (existingFriendship) {
      throw new ConflictException('You are already friends');
    }

    // Create the friendship (Mutual relationship)
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        friends: { connect: { id: friendId } },
      },
    });

    await this.prisma.user.update({
      where: { id: friendId },
      data: {
        friends: { connect: { id: userId } },
      },
    });

    return { message: 'Friend added successfully' };
  }

  // Remove a friend
  async removeFriend(userId: number, friendId: number) {
    // Check if both users exist
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    const friend = await this.prisma.user.findUnique({ where: { id: friendId } });

    if (!user || !friend) {
      throw new NotFoundException('User or Friend not found');
    }

    // Check if they are friends
    const existingFriendship = await this.prisma.user.findFirst({
      where: {
        AND: [
          { id: userId },
          { friends: { some: { id: friendId } } },
        ],
      },
    });

    if (!existingFriendship) {
      throw new NotFoundException('Friendship not found');
    }

    // Remove the friendship (Mutual disconnection)
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        friends: { disconnect: { id: friendId } },
      },
    });

    await this.prisma.user.update({
      where: { id: friendId },
      data: {
        friends: { disconnect: { id: userId } },
      },
    });

    return { message: 'Friend removed successfully' };
  }

  // List friends
  async listFriends(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { friends: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user.friends;
  }
}
