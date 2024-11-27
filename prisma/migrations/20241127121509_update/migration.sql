/*
  Warnings:

  - Made the column `field` on table `Partner` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "Partner" ALTER COLUMN "field" SET NOT NULL;
