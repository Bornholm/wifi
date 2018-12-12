package wifi

// TriggerScan triggers a scan of the neirby access points with the given interface
func (c *Client) TriggerScan(ifi *Interface) error {
	return c.c.TriggerScan(ifi)
}

// ScanResult retrieves all the neirby access points for the given interface
func (c *Client) ScanResult(ifi *Interface) ([]*BSS, error) {
	return c.c.ScanResult(ifi)
}
