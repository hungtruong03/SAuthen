/*
  Warnings:

  - The `status` column on the `Partner` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- CreateEnum
CREATE TYPE "Status" AS ENUM ('Unverified', 'Verified');

-- AlterTable
ALTER TABLE "Partner" DROP COLUMN "status",
ADD COLUMN     "status" "Status" NOT NULL DEFAULT 'Unverified';
