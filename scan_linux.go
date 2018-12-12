package wifi

import (
	"github.com/pkg/errors"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/wifi/internal/nl80211"
)

var (
	errDeviceOrResourceBusy = errors.New("device or resource busy")
)

// TriggerScan triggers a scan of the given network interface
func (c *client) TriggerScan(ifi *Interface) error {

	family, err := c.c.GetFamily(nl80211.GenlName)
	if err != nil {
		return err
	}

	var scanGroup *genetlink.MulticastGroup
	for _, g := range family.Groups {
		if g.Name == "scan" {
			scanGroup = &g
			break
		}
	}

	if scanGroup == nil {
		return errors.New("no scan multicast group")
	}

	if err := c.c.JoinGroup(scanGroup.ID); err != nil {
		return err
	}
	defer c.c.LeaveGroup(scanGroup.ID)

	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return err
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdTriggerScan,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	_, err = c.c.Send(msg, c.familyID, flags)
	if err != nil {
		if err.Error() != errDeviceOrResourceBusy.Error() {
			return err
		}
	}

	// Wait for "CmdNewScanResults" notifications
	for {
		msgs, _, err := c.c.Receive()
		if err != nil {
			if err.Error() != errDeviceOrResourceBusy.Error() {
				return err
			}
			continue
		}
		for _, m := range msgs {
			if m.Header.Command == nl80211.CmdNewScanResults {
				return nil
			}
		}
	}

	return nil
}

func (c *client) ScanResult(ifi *Interface) ([]*BSS, error) {

	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return nil, err
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetScan,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(msg, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	bsses := make([]*BSS, 0)
	for _, m := range msgs {

		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		for _, a := range attrs {
			if a.Type != uint16(nl80211.AttrBss) {
				continue
			}
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}
			var bss BSS
			if err := (&bss).parseAttributes(nattrs); err != nil {
				return nil, err
			}
			bsses = append(bsses, &bss)
		}

	}

	return bsses, nil
}
