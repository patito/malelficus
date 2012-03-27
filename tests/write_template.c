

int main() {
    int fd;
    
    fd = open("./echo", O_RDWR|O_CREAT);
    
    if (fd == -1) {
        printf("aborting ...\n");
        return 1;
    }
    
    if (write(fd, &elf_header, sizeof(elf_header)) != sizeof (elf_header)) {
        printf("erro when writing header\n");
        return 1;
    }
    
    if (write(fd, segments, sizeof(segments)) != sizeof(segments)) {
        printf("error when writing the segments...\n");
        return 1;
    }
    
    if (write(fd, &sht, sizeof(sht)) != sizeof(sht)) {
        printf("error when writing sht\n");
        return 1;
    }
    
    close(fd);
}



