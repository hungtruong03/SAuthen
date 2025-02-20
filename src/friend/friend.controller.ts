import { Controller, Post, Delete, Get, Body, Request, UnauthorizedException } from '@nestjs/common';
import { FriendsService } from './friend.service';

@Controller('friend')
export class FriendsController {
  constructor(private friendsService: FriendsService) { }

  @Post('add')
  async addFriend(@Body() { friendId }: { friendId: string }, @Request() req) {
    if (req.role !== 'USER') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    const userId = req.userId;
    return this.friendsService.addFriend(userId, friendId);
  }

  @Delete('remove')
  async removeFriend(@Body() { friendId }: { friendId: string }, @Request() req) {
    if (req.role !== 'USER') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    const userId = req.userId;
    return this.friendsService.removeFriend(userId, friendId);
  }

  @Get('list')
  async listFriends(@Request() req) {
    if (req.role !== 'USER') {
      throw new UnauthorizedException('You are not authorized to access this resource');
    }

    const userId = req.userId;
    return this.friendsService.listFriends(userId);
  }
}