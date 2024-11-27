import { Module, MiddlewareConsumer, RequestMethod, NestModule } from '@nestjs/common';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { JwtMiddleware } from '../middlewares/jwt.middleware';

@Module({
    imports: [PrismaModule],
    providers: [AdminService],
    controllers: [AdminController],
})

export class AdminModule implements NestModule {
    configure(consumer: MiddlewareConsumer) {
        consumer
            .apply(JwtMiddleware)
            .forRoutes({ path: 'admin/*', method: RequestMethod.ALL });
    }
}