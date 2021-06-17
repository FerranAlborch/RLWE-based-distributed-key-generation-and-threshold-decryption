# We set the working directory (wherever we have the csv files) and import
# ggplot2 library
#install.packages("tidyverse")
library(ggplot2)
setwd("~/Desktop/Threshold Decryption and KeyGen protocols")


# Key Generation dependence on n active adversary ############################

# We import the csv files
kg128 <- read.csv2("keygen128.csv", header = FALSE)
kg256 <- read.csv2("keygen256.csv", header = FALSE)
kg512 <- read.csv2("keygen512.csv", header = FALSE)
kg1024 <- read.csv2("keygen1024.csv", header = FALSE)
kg2048 <- read.csv2("keygen2048.csv", header = FALSE)

# We put the dataframes as vectors
auxkg128 <- as.vector(kg128$V1)
timeskg128 <- as.double(auxkg128)
auxkg256 <- as.vector(kg256$V1)
timeskg256 <- as.double(auxkg256)
auxkg512 <- as.vector(kg512$V1)
timeskg512 <- as.double(auxkg512)
auxkg1024 <- as.vector(kg1024$V1)
timeskg1024 <- as.double(auxkg1024)
auxkg2048 <- as.vector(kg2048$V1)
timeskg2048 <- as.double(auxkg2048)

# We compute the mean on every value of n
meankg128 <- mean(timeskg128, na.rm = TRUE)
meankg256 <- mean(timeskg256, na.rm = TRUE)
meankg512 <- mean(timeskg512, na.rm = TRUE)
meankg1024 <- mean(timeskg1024, na.rm = TRUE)
meankg2048 <- mean(timeskg2048, na.rm = TRUE)

# We create dataframe for ggplot
n <- c(128,256,512,1024,2048)
mskg <- c(meankg128,meankg256,meankg512,meankg1024,meankg2048)
kg_data <- data.frame("n" = n, "times" = mskg)
p <- ggplot(kg_data, aes(x = n, y = times)) + geom_point() + geom_line() + labs(
            title = "Average key generation time depending on n", y = "Times in ms") +
            expand_limits(x = 250, y = 0) + 
            scale_y_continuous(breaks = seq(0,30000,by = 5000))
ggsave("keygentimes.pdf")


# Decryption dependence on n active adversary ################################

# We import the csv files
dec128 <- read.csv2("decrypt128.csv", header = FALSE)
dec256 <- read.csv2("decrypt256.csv", header = FALSE)
dec512 <- read.csv2("decrypt512.csv", header = FALSE)
dec1024 <- read.csv2("decrypt1024.csv", header = FALSE)
dec2048 <- read.csv2("decrypt2048.csv", header = FALSE)

# We put the dataframes as vectors
auxdec128 <- as.vector(dec128$V1)
timesdec128 <- as.double(auxdec128)
auxdec256 <- as.vector(dec256$V1)
timesdec256 <- as.double(auxdec256)
auxdec512 <- as.vector(dec512$V1)
timesdec512 <- as.double(auxdec512)
auxdec1024 <- as.vector(dec1024$V1)
timesdec1024 <- as.double(auxdec1024)
auxdec2048 <- as.vector(dec2048$V1)
timesdec2048 <- as.double(auxdec2048)

# We compute the mean on every value of n
meandec128 <- mean(timesdec128, na.rm = TRUE)
meandec256 <- mean(timesdec256, na.rm = TRUE)
meandec512 <- mean(timesdec512, na.rm = TRUE)
meandec1024 <- mean(timesdec1024, na.rm = TRUE)
meandec2048 <- mean(timesdec2048, na.rm = TRUE)

# We create both vectors and we plot
msdec <- c(meandec128,meandec256,meandec512,meandec1024,meandec2048)
kg_data <- data.frame("n" = n, "times" = msdec)
p <- ggplot(kg_data, aes(x = n, y = times)) + geom_point() + geom_line() + labs(
  title = "Average decryption time depending on n", y = "Times in ms") 
ggsave("decrypttimes.pdf")


# Key generation dependence on t active adversary #############################

# We import the csv files
kgt0 <- read.csv2("keygent0.csv", header = FALSE)
kgt1 <- read.csv2("keygent1.csv", header = FALSE)
kgt2 <- read.csv2("keygen128.csv", header = FALSE)
kgt3 <- read.csv2("keygent3.csv", header = FALSE)

# We put the dataframes as vectors
auxkgt0 <- as.vector(kgt0$V1)
timeskgt0 <- as.double(auxkgt0)
auxkgt1 <- as.vector(kgt1$V1)
timeskgt1 <- as.double(auxkgt1)
auxkgt2 <- as.vector(kgt2$V1)
timeskgt2 <- as.double(auxkgt2)
auxkgt3 <- as.vector(kgt3$V1)
timeskgt3 <- as.double(auxkgt3)

# We compute the mean on every value of n
meankgt0 <- mean(timeskgt0, na.rm = TRUE)
meankgt1 <- mean(timeskgt1, na.rm = TRUE)
meankgt2 <- mean(timeskgt2, na.rm = TRUE)
meankgt3 <- mean(timeskgt3, na.rm = TRUE)

# We create both vectors and we plot
t <- c(0,1,2,3)
mskgt <- c(meankgt0,meankgt1,meankgt2,meankgt3)
kg_data <- data.frame("t" = t, "times" = mskgt)
p <- ggplot(kg_data, aes(x = t, y = times)) + geom_point() + geom_line() + labs(
  title = "Average key generation time depending on t", y = "Times in ms")
ggsave("keygentimest.pdf")


# Decryption dependence on t active adversary #################################

# We import the csv files
dect0 <- read.csv2("decryptt0.csv", header = FALSE)
dect1 <- read.csv2("decryptt1.csv", header = FALSE)
dect2 <- read.csv2("decrypt128.csv", header = FALSE)
dect3 <- read.csv2("decryptt3.csv", header = FALSE)


# We put the dataframes as vectors
auxdect0 <- as.vector(dect0$V1)
timesdect0 <- as.double(auxdect0)
auxdect1 <- as.vector(dect1$V1)
timesdect1 <- as.double(auxdect1)
auxdect2 <- as.vector(dect2$V1)
timesdect2 <- as.double(auxdect2)
auxdect3 <- as.vector(dect3$V1)
timesdect3 <- as.double(auxdect3)

# We compute the mean on every value of n
meandect0 <- mean(timesdect0, na.rm = TRUE)
meandect1 <- mean(timesdect1, na.rm = TRUE)
meandect2 <- mean(timesdect2, na.rm = TRUE)
meandect3 <- mean(timesdect3, na.rm = TRUE)

# We create both vectors and we plot
msdect <- c(meandect0,meandect1,meandect2,meandect3)
kg_data <- data.frame("t" = t, "times" = msdect)
p <- ggplot(kg_data, aes(x = t, y = times)) + geom_point() + geom_line() + labs(
  title = "Average decryption time depending on t", y = "Times in ms") 
ggsave("decrypttimest.pdf")


# Key Generation dependence on n passive adversary ############################

# We import the csv files
kg128pas <- read.csv2("keygen_128_3_2.csv", header = FALSE)
kg256pas <- read.csv2("keygen_256_3_2.csv", header = FALSE)
kg512pas <- read.csv2("keygen_512_3_2.csv", header = FALSE)
kg1024pas <- read.csv2("keygen_1024_3_2.csv", header = FALSE)
kg2048pas <- read.csv2("keygen_2048_3_2.csv", header = FALSE)

# We put the dataframes as vectors
auxkg128pas <- as.vector(kg128pas$V1)
timeskg128pas <- as.double(auxkg128pas)
auxkg256pas <- as.vector(kg256pas$V1)
timeskg256pas <- as.double(auxkg256pas)
auxkg512pas <- as.vector(kg512pas$V1)
timeskg512pas <- as.double(auxkg512pas)
auxkg1024pas <- as.vector(kg1024pas$V1)
timeskg1024pas <- as.double(auxkg1024pas)
auxkg2048pas <- as.vector(kg2048pas$V1)
timeskg2048pas <- as.double(auxkg2048pas)

# We compute the mean on every value of n
meankg128pas <- mean(timeskg128pas, na.rm = TRUE)
meankg256pas <- mean(timeskg256pas, na.rm = TRUE)
meankg512pas <- mean(timeskg512pas, na.rm = TRUE)
meankg1024pas <- mean(timeskg1024pas, na.rm = TRUE)
meankg2048pas <- mean(timeskg2048pas, na.rm = TRUE)

# We create dataframe for ggplot
mskgpas <- c(meankg128pas,meankg256pas,meankg512pas,meankg1024pas,meankg2048pas)
kg_datapas <- data.frame("n" = n, "times" = mskgpas)
p <- ggplot(kg_datapas, aes(x = n, y = times)) + geom_point() + geom_line() + labs(
  title = "Average key generation time depending on n", y = "Times in ms") 
ggsave("keygentimespas.pdf")


# Decryption dependence on n passive adversary ################################

# We import the csv files
dec128pas <- read.csv2("decrypt_128_3_2.csv", header = FALSE)
dec256pas <- read.csv2("decrypt_256_3_2.csv", header = FALSE)
dec512pas <- read.csv2("decrypt_512_3_2.csv", header = FALSE)
dec1024pas <- read.csv2("decrypt_1024_3_2.csv", header = FALSE)
dec2048pas <- read.csv2("decrypt_2048_3_2.csv", header = FALSE)

# We put the dataframes as vectors
auxdec128pas <- as.vector(dec128pas$V1)
timesdec128pas <- as.double(auxdec128pas)
auxdec256pas <- as.vector(dec256pas$V1)
timesdec256pas <- as.double(auxdec256pas)
auxdec512pas <- as.vector(dec512pas$V1)
timesdec512pas <- as.double(auxdec512pas)
auxdec1024pas <- as.vector(dec1024pas$V1)
timesdec1024pas <- as.double(auxdec1024pas)
auxdec2048pas <- as.vector(dec2048pas$V1)
timesdec2048pas <- as.double(auxdec2048pas)

# We compute the mean on every value of n
meandec128pas <- mean(timesdec128pas, na.rm = TRUE)
meandec256pas <- mean(timesdec256pas, na.rm = TRUE)
meandec512pas <- mean(timesdec512pas, na.rm = TRUE)
meandec1024pas <- mean(timesdec1024pas, na.rm = TRUE)
meandec2048pas <- mean(timesdec2048pas, na.rm = TRUE)

# We create both vectors and we plot
msdecpas <- c(meandec128pas,meandec256pas,meandec512pas,meandec1024pas,meandec2048pas)
kg_datapas <- data.frame("n" = n, "times" = msdecpas)
p <- ggplot(kg_datapas, aes(x = n, y = times)) + geom_point() + geom_line() + labs(
  title = "Average decryption time depending on n", y = "Times in ms") 
ggsave("decrypttimespas.pdf")


# Key generation dependence on t passive adversary #############################

# We import the csv files
kgt0pas <- read.csv2("keygen_128_1_0.csv", header = FALSE)
kgt1pas <- read.csv2("keygen_128_2_1.csv", header = FALSE)
kgt2pas <- read.csv2("keygen_128_3_2.csv", header = FALSE)
kgt3pas <- read.csv2("keygen_128_4_3.csv", header = FALSE)

# We put the dataframes as vectors
auxkgt0pas <- as.vector(kgt0pas$V1)
timeskgt0pas <- as.double(auxkgt0pas)
auxkgt1pas <- as.vector(kgt1pas$V1)
timeskgt1pas <- as.double(auxkgt1pas)
auxkgt2pas <- as.vector(kgt2pas$V1)
timeskgt2pas <- as.double(auxkgt2pas)
auxkgt3pas <- as.vector(kgt3pas$V1)
timeskgt3pas <- as.double(auxkgt3pas)

# We compute the mean on every value of n
meankgt0pas <- mean(timeskgt0pas, na.rm = TRUE)
meankgt1pas <- mean(timeskgt1pas, na.rm = TRUE)
meankgt2pas <- mean(timeskgt2pas, na.rm = TRUE)
meankgt3pas <- mean(timeskgt3pas, na.rm = TRUE)

# We create both vectors and we plot
mskgtpas <- c(meankgt0pas,meankgt1pas,meankgt2pas,meankgt3pas)
kg_datapas <- data.frame("t" = t, "times" = mskgtpas)
p <- ggplot(kg_datapas, aes(x = t, y = times)) + geom_point() + geom_line() + labs(
  title = "Average key generation time depending on t", y = "Times in ms")
ggsave("keygentimestpas.pdf")


# Decryption dependence on t passive adversary #################################

# We import the csv files
dect0pas <- read.csv2("decrypt_128_1_0.csv", header = FALSE)
dect1pas <- read.csv2("decrypt_128_2_1.csv", header = FALSE)
dect2pas <- read.csv2("decrypt_128_3_2.csv", header = FALSE)
dect3pas <- read.csv2("decrypt_128_4_3.csv", header = FALSE)


# We put the dataframes as vectors
auxdect0pas <- as.vector(dect0pas$V1)
timesdect0pas <- as.double(auxdect0pas)
auxdect1pas <- as.vector(dect1pas$V1)
timesdect1pas <- as.double(auxdect1pas)
auxdect2pas <- as.vector(dect2pas$V1)
timesdect2pas <- as.double(auxdect2pas)
auxdect3pas <- as.vector(dect3pas$V1)
timesdect3pas <- as.double(auxdect3pas)

# We compute the mean on every value of n
meandect0pas <- mean(timesdect0pas, na.rm = TRUE)
meandect1pas <- mean(timesdect1pas, na.rm = TRUE)
meandect2pas <- mean(timesdect2pas, na.rm = TRUE)
meandect3pas <- mean(timesdect3pas, na.rm = TRUE)

# We create both vectors and we plot
msdectpas <- c(meandect0pas,meandect1pas,meandect2pas,meandect3pas)
kg_datapas <- data.frame("t" = t, "times" = msdectpas)
p <- ggplot(kg_datapas, aes(x = t, y = times)) + geom_point() + geom_line() + labs(
  title = "Average decryption time depending on t", y = "Times in ms")
ggsave("decrypttimestpas.pdf")

