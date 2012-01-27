-- Host: localhost    Database: bad_traffic
-- ------------------------------------------------------
-- Server version	5.1.52

--
-- Table structure for table `blocked_hosts`
--

DROP TABLE IF EXISTS `blocked_hosts`;
CREATE TABLE `blocked_hosts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ipaddress` varchar(18) NOT NULL,
  `reason` text NOT NULL,
  `date_blocked` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `date_expired` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `expired` tinyint(4) NOT NULL DEFAULT '0',
  `reporting_host` varchar(80) NOT NULL DEFAULT 'localhost',
  `whitelisted` tinyint(1) NOT NULL DEFAULT '0',
  `category` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `categories`;
CREATE TABLE `categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `category` varchar(20) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;
