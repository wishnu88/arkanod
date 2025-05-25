# -*- coding: utf-8 -*-
"""
Poll EVC (Electronic Volume Corrector) data and archive log periodically using the 0-based address MODBUS protocol.

License:
    MIT License

    Copyright (c) 2024-2025 Wishnu Adhi Pahlevi <wishnu@pahlevi.id>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the “Software”), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

The evc module database constants initialization file.
"""

TRIGGER_REQ_DATALOG = """
CREATE TRIGGER `%s_REQ_DATALOG` AFTER UPDATE ON `%s` FOR EACH ROW BEGIN
    DECLARE xDate_Start INT unsigned;
    DECLARE xDate_End INT unsigned;
    DECLARE devID INT unsigned;
    DECLARE hourly_retention INT unsigned;
    DECLARE daily_retention INT unsigned;
    
    SET devID=new.deviceID;

    SELECT UNIX_TIMESTAMP(Date_Start), UNIX_TIMESTAMP(Date_End) INTO xDate_Start, xDate_End FROM %s_update_check WHERE deviceID = devID;

    SET hourly_retention=FLOOR((xDate_End - xDate_Start) / 3600);

    IF hourly_retention > 0 THEN
        INSERT INTO %s_request_log (deviceID, archiveLog, logRetention) VALUES (devID, 0, hourly_retention);
    END IF;

    IF hourly_retention > 48 THEN
        SET daily_retention=FLOOR((xDate_End - xDate_Start) / 86400);
        INSERT INTO %s_request_log (deviceID, archiveLog, logRetention) VALUES (devID, 1, daily_retention);
    END IF;
END"""

EVENT_NOT_UPDATE_CHECK = """
CREATE EVENT IF NOT EXISTS `%s_NOT_UPDATE_CHECK` ON SCHEDULE EVERY 1 HOUR STARTS '2021-12-25 00:00:00' ON COMPLETION NOT PRESERVE ENABLE DO BEGIN
    DELETE FROM `%s_update_check` WHERE Date_End IS NOT NULL;
    INSERT INTO %s_update_check (`deviceID`,`Date_Start`) SELECT deviceID, LastUpdated FROM %s_current_log WHERE (UNIX_TIMESTAMP() - UNIX_TIMESTAMP(LastUpdated)) > 3600 AND deviceID NOT IN (SELECT deviceID FROM %s_update_check);
END """

DATA_TYPE = {
    'float16': 'float',
    'float32': 'float',
    'float64': 'double',
    'int8': 'tinyint',
    'int16': 'smallint',
    'int32': 'int',
    'int64': 'bigint',
    'uint8': 'tinyint UNSIGNED',
    'uint16': 'smallint UNSIGNED',
    'uint32': 'int UNSIGNED',
    'uint64': 'bigint UNSIGNED',
    'string':'text',
    'dt1': 'datetime',
    'dt2': 'datetime',
    'bits': 'bit(8)'
}

OPER_TABLES = {
    'devices': "(`id` int AUTO_INCREMENT PRIMARY KEY, `mbmaster_name` varchar(30) NOT NULL, `slaveID` tinyint NOT NULL DEFAULT 1, DeviceCreated DATETIME DEFAULT current_timestamp(), LastUpdated DATETIME DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP()) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4",
    'request_log': "(`id` BIGINT AUTO_INCREMENT PRIMARY KEY, `deviceID` int NOT NULL, `archiveLog` tinyint NOT NULL, `logRetention` smallint NOT NULL, `requestStatus` tinyint NOT NULL DEFAULT 0, `RequestCreated` datetime NOT NULL DEFAULT current_timestamp(), `LastUpdated` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4",
    'update_check': "(`id` INT AUTO_INCREMENT PRIMARY KEY, `deviceID` int NOT NULL, `Date_Start` datetime NOT NULL, `Date_End` datetime DEFAULT NULL) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4"
}
