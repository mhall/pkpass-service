import { Entity, PrimaryGeneratedColumn, Column, Unique, OneToMany } from "typeorm";
import { Registration } from './Registration';

@Entity()
@Unique(["passTypeId", "serialNumber"])
export class Pass {

    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    passTypeId: string;

    @Column()
    serialNumber: string;

    @Column()
    authenticationToken: string;

    @Column()
    hash: string;

    @Column()
    updatedAt: Date;

    @OneToMany(type => Registration, registration => registration.pass)
    registrations: Registration[];

}
